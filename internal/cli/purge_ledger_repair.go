package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
)

const legacyPurgeAttestationMaxBytes int64 = 64 << 10

var errPurgeLedgerRepairMutation = errors.New("purge ledger repair mutation failed")

type purgeLedgerRepairResult struct {
	Generations  int
	Receipts     int
	Attestations int
	Commit       plumbing.Hash
	Changed      bool
}

func legacyPurgePlanAttestationPath(target string, generation uint64, transactionID string) string {
	return remoteStatePath(target, path.Join("purge-migrations", fmt.Sprintf("%020d-%s.json", generation, transactionID)))
}

func legacyPurgePlanAttestationForEnvelope(target string, envelope purgeLedgerEnvelope, receiptBody []byte) (pub.LegacyPurgePlanAttestation, []byte, error) {
	var result pub.LegacyPurgePlanAttestation
	if envelope.checkpoint.Schema != pub.CheckpointSchemaV1 || envelope.checkpoint.PlanSHA256 != "" || len(envelope.plan.PurgeURLs) == 0 {
		return result, nil, errors.New("legacy purge attestation requires a v1 checkpoint and a nonempty purge plan")
	}
	planSHA, err := envelope.plan.Digest()
	if err != nil {
		return result, nil, err
	}
	result = pub.LegacyPurgePlanAttestation{
		Target:           pub.TargetName(target),
		Generation:       envelope.generation.Generation,
		TransactionID:    envelope.checkpoint.TransactionID,
		AnchorCommit:     envelope.anchor.String(),
		GenerationSHA256: envelope.generationSHA,
		CheckpointSHA256: envelope.checkpointSHA,
		PlanSHA256:       planSHA,
		ReceiptSHA256:    digestBytesCLI(receiptBody),
	}
	body, err := result.Canonical()
	return result, body, err
}

// inspectLegacyPurgePlanAttestation validates the explicit migration witness
// for one v1/nonempty publication envelope. The provider receipt must still be
// byte-identical to the receipt committed at the immutable publication anchor;
// an attestation can never bless a later replacement receipt.
func inspectLegacyPurgePlanAttestation(canonical *state.Store, target string, envelope purgeLedgerEnvelope, receiptPath string, receiptBody []byte) (*verify.Finding, error) {
	planSHA, err := envelope.plan.Digest()
	if err != nil {
		return nil, err
	}
	for _, control := range []struct {
		path   string
		digest string
	}{
		{path: remoteStatePath(target, "generation.json"), digest: envelope.generationSHA},
		{path: remoteStatePath(target, "checkpoint.json"), digest: envelope.checkpointSHA},
		{path: remoteStatePath(target, "plan.json"), digest: planSHA},
	} {
		actual, exists, err := hashCanonicalPathOptionalAt(canonical, envelope.anchor, control.path)
		if err != nil {
			return nil, err
		}
		if !exists || actual != control.digest {
			finding := purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PLAN_BINDING_INVALID", control.path, "legacy purge control document differs from its immutable publication anchor")
			return &finding, nil
		}
	}
	anchorReceipt, anchorExists, err := readCanonicalBytesAt(canonical, envelope.anchor, receiptPath, canonicalPurgeReceiptMaxBytes)
	if err != nil {
		return nil, err
	}
	if !anchorExists || !bytes.Equal(anchorReceipt, receiptBody) {
		finding := purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PLAN_BINDING_INVALID", receiptPath, "legacy purge receipt differs from its immutable publication anchor")
		return &finding, nil
	}
	evidence, err := pub.DecodePurgeEvidence(anchorReceipt)
	if err != nil {
		finding := purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PLAN_BINDING_INVALID", receiptPath, "legacy purge receipt at the immutable publication anchor is invalid")
		return &finding, nil
	}
	urlsSHA, err := pub.PurgeURLsDigest(envelope.plan.PurgeURLs)
	if err != nil {
		return nil, err
	}
	if evidence.Target != pub.TargetName(target) || evidence.TransactionID != envelope.checkpoint.TransactionID ||
		evidence.Generation != envelope.generation.Generation || evidence.GenerationSHA256 != envelope.generationSHA ||
		evidence.PlanSHA256 != planSHA || evidence.CheckpointSHA256 != envelope.checkpointSHA ||
		evidence.URLCount != len(envelope.plan.PurgeURLs) || evidence.URLsSHA256 != urlsSHA {
		finding := purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PLAN_BINDING_INVALID", receiptPath, "legacy purge receipt disagrees with its immutable publication envelope")
		return &finding, nil
	}
	latestFull := uint64(0)
	for _, attempt := range evidence.Attempts {
		if attempt.Purpose == pub.PurgeAttemptFull {
			latestFull = attempt.ID
		}
	}
	if latestFull == 0 || evidence.ValidateFullClosure(latestFull, envelope.plan.PurgeURLs) != nil {
		finding := purgeLedgerFinding(verify.CategoryCoverage, "LOCAL_PLAN_BINDING_MISSING", receiptPath, "legacy purge receipt has no completed full closure to attest")
		return &finding, nil
	}
	_, expectedBody, err := legacyPurgePlanAttestationForEnvelope(target, envelope, anchorReceipt)
	if err != nil {
		return nil, err
	}
	attestationPath := legacyPurgePlanAttestationPath(target, envelope.generation.Generation, envelope.checkpoint.TransactionID)
	head, err := canonical.HeadHash()
	if err != nil {
		return nil, err
	}
	body, exists, err := readCanonicalBytesAt(canonical, head, attestationPath, legacyPurgeAttestationMaxBytes)
	if err != nil {
		return nil, err
	}
	if !exists {
		finding := purgeLedgerFinding(verify.CategoryCoverage, "LOCAL_PLAN_BINDING_MISSING", attestationPath, "legacy v1 checkpoint has no explicit purge plan attestation; run fsck --repair-purge-ledger with this target")
		return &finding, nil
	}
	if _, err := pub.DecodeLegacyPurgePlanAttestation(body); err != nil || !bytes.Equal(body, expectedBody) {
		finding := purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PLAN_BINDING_INVALID", attestationPath, "legacy purge plan attestation is invalid or disagrees with its immutable publication envelope")
		return &finding, nil
	}
	return nil, nil
}

// legacyPurgeEnvelopeForClosure resolves the immutable publication anchor for
// a v1 checkpoint closure. It is used only after the generation, checkpoint,
// and plan have passed their ordinary structural checks.
func legacyPurgeEnvelopeForClosure(canonical *state.Store, target string, generation pub.TargetGeneration, generationBody []byte, checkpoint pub.Checkpoint, checkpointBody []byte, plan pub.Plan) (purgeLedgerEnvelope, error) {
	var result purgeLedgerEnvelope
	anchor, anchoredGeneration, err := targetGenerationPublicationState(canonical, target, generation.Generation)
	if err != nil {
		return result, err
	}
	anchorGenerationBody, exists, err := readCanonicalBytesAt(canonical, anchor, remoteStatePath(target, "generation.json"), 16<<20)
	if err != nil {
		return result, err
	}
	if !exists || anchoredGeneration.Target != generation.Target || !bytes.Equal(anchorGenerationBody, generationBody) {
		return result, errors.New("legacy purge publication anchor disagrees with the current generation")
	}
	result = purgeLedgerEnvelope{
		anchor:        anchor,
		generationSHA: digestBytesCLI(generationBody),
		generation:    generation,
		checkpointSHA: digestBytesCLI(checkpointBody),
		checkpoint:    checkpoint,
		plan:          plan,
	}
	return result, nil
}

// validateCanonicalCheckpointPlanBinding accepts a v1/nonempty plan only when
// the explicit anchor-bound migration witness is present. It is shared by
// current, intent-scoped, and historical verification readers so migration
// cannot make publish pass while leaving restore or L3 permanently unusable.
func validateCanonicalCheckpointPlanBinding(canonical *state.Store, target string, generation pub.TargetGeneration, generationBody []byte, checkpoint pub.Checkpoint, checkpointBody []byte, plan pub.Plan) error {
	planSHA, err := plan.Digest()
	if err != nil {
		return err
	}
	if checkpoint.PlanSHA256 != "" {
		if checkpoint.PlanSHA256 != planSHA {
			return errors.New("canonical publication plan disagrees with its committed checkpoint")
		}
		return nil
	}
	if len(plan.PurgeURLs) == 0 {
		return nil
	}
	if canonical == nil {
		return errors.New("legacy v1 nonempty purge plan requires canonical migration evidence")
	}
	envelope, err := legacyPurgeEnvelopeForClosure(canonical, target, generation, generationBody, checkpoint, checkpointBody, plan)
	if err != nil {
		return err
	}
	receiptPath := purgeLedgerReceiptPath(target, generation.Generation, checkpoint.TransactionID)
	head, err := canonical.HeadHash()
	if err != nil {
		return err
	}
	receiptBody, exists, err := readCanonicalBytesAt(canonical, head, receiptPath, canonicalPurgeReceiptMaxBytes)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("legacy v1 nonempty purge plan has no retained canonical receipt")
	}
	finding, err := inspectLegacyPurgePlanAttestation(canonical, target, envelope, receiptPath, receiptBody)
	if err != nil {
		return err
	}
	if finding != nil {
		return fmt.Errorf("%s: %s", finding.Code, finding.Message)
	}
	return nil
}

// repairCanonicalPurgeLedger performs a local-only, additive repair. It never
// creates a provider client and never deletes canonical evidence. Every staged
// receipt is copied byte-for-byte from its first atomic publication commit;
// every legacy attestation is deterministically recomputed from that anchor.
func repairCanonicalPurgeLedger(ctx context.Context, canonical *state.Store, runtime *config.Config, target, transactionDir string) (purgeLedgerRepairResult, error) {
	var result purgeLedgerRepairResult
	if canonical == nil || runtime == nil {
		return result, errors.New("purge ledger repair requires canonical state and configuration")
	}
	history, err := canonical.History()
	if err != nil {
		return result, err
	}
	if len(history) == 0 {
		return result, errors.New("purge ledger repair requires initialized canonical state")
	}
	historyIndex := make(map[plumbing.Hash]int, len(history))
	for index, commit := range history {
		historyIndex[commit] = index
	}
	generationPath := remoteStatePath(target, "generation.json")
	checkpointPath := remoteStatePath(target, "checkpoint.json")
	planPath := remoteStatePath(target, "plan.json")
	head := history[0]
	staged := make(map[string]string)
	expectedReceipts := make(map[string]struct{})
	expectedAttestations := make(map[string]struct{})
	var lastIdentity purgeLedgerEnvelopeIdentity
	var lastClosureIdentity purgeLedgerClosureIdentity
	var lastEnvelope purgeLedgerEnvelope
	var lastGeneration uint64
	publicationSeen := false
	stageIndex := 0
	stageBody := func(canonicalPath string, body []byte) error {
		filename := filepath.Join(transactionDir, fmt.Sprintf("purge-ledger-repair-%06d", stageIndex))
		stageIndex++
		if err := writeExclusiveBytes(filename, body); err != nil {
			return err
		}
		staged[canonicalPath] = filename
		return nil
	}

	for index := len(history) - 1; index >= 0; index-- {
		commit := history[index]
		identity, present, err := purgeLedgerEnvelopeIdentityAt(canonical, commit, generationPath, checkpointPath, planPath)
		if err != nil {
			return result, err
		}
		if present == 0 {
			if publicationSeen {
				return result, fmt.Errorf("historical publication control triplet was deleted at %s", commit)
			}
			continue
		}
		if present != 3 {
			return result, fmt.Errorf("historical publication control triplet is partial at %s: found %d of 3 files", commit, present)
		}
		if publicationSeen && identity == lastIdentity {
			closureIdentity, closurePresent, closureIdentityErr := purgeLedgerClosureIdentityAt(canonical, commit, target, lastEnvelope.generation)
			if closureIdentityErr != nil {
				return result, closureIdentityErr
			}
			if closurePresent != 4 || closureIdentity != lastClosureIdentity {
				return result, fmt.Errorf("generation %d content or intent-local publication closure changed without advancing the generation at %s", lastGeneration, commit)
			}
			continue
		}
		// A legitimate next publication necessarily changes the generation
		// blob and is checked below. Reusing the generation blob with changed
		// siblings is always a same-generation rewrite.
		if publicationSeen && identity.generation == lastIdentity.generation {
			return result, fmt.Errorf("generation %d checkpoint or plan changed without advancing the generation at %s", lastGeneration, commit)
		}
		envelope, err := loadPurgeLedgerEnvelopeAt(canonical, commit, target, generationPath, checkpointPath, planPath)
		if err != nil {
			return result, fmt.Errorf("invalid historical publication envelope at %s: %w", commit, err)
		}
		if _, closureExists, closureErr := loadHistoricalPublicationClosureAtForMigration(canonical, target, commit); closureErr != nil || !closureExists {
			if closureErr == nil {
				closureErr = errors.New("historical target publication closure is absent")
			}
			return result, fmt.Errorf("invalid historical publication closure at %s: %w", commit, closureErr)
		}
		closureIdentity, closurePresent, closureIdentityErr := purgeLedgerClosureIdentityAt(canonical, commit, target, envelope.generation)
		if closureIdentityErr != nil {
			return result, closureIdentityErr
		}
		if closurePresent != 4 {
			return result, fmt.Errorf("historical content and intent-local publication closure is incomplete at %s", commit)
		}
		wantGeneration, wantParent := uint64(1), uint64(0)
		if publicationSeen {
			wantGeneration, wantParent = lastGeneration+1, lastGeneration
		}
		if envelope.generation.Generation != wantGeneration || envelope.generation.ParentGeneration != wantParent {
			return result, fmt.Errorf("historical generation chain got generation=%d parent=%d, want generation=%d parent=%d", envelope.generation.Generation, envelope.generation.ParentGeneration, wantGeneration, wantParent)
		}
		if publicationSeen {
			ancestor, ancestryErr := canonical.IsAncestor(lastEnvelope.anchor, envelope.anchor)
			if ancestryErr != nil {
				return result, ancestryErr
			}
			if !ancestor {
				return result, fmt.Errorf("generation %d publication anchor does not descend from generation %d anchor", envelope.generation.Generation, lastGeneration)
			}
		}
		if err := validateHistoricalDesiredCommit(canonical, envelope.generation, commit, index, historyIndex); err != nil {
			return result, err
		}
		planSHA, err := envelope.plan.Digest()
		if err != nil {
			return result, err
		}
		if envelope.checkpoint.PlanSHA256 != "" && envelope.checkpoint.PlanSHA256 != planSHA {
			return result, errors.New("historical checkpoint plan binding is invalid")
		}
		if envelope.checkpoint.PlanSHA256 == "" && envelope.checkpoint.Schema != pub.CheckpointSchemaV1 {
			return result, errors.New("historical checkpoint lacks a plan binding outside the v1 migration boundary")
		}
		result.Generations++
		if len(envelope.plan.PurgeURLs) != 0 {
			receiptPath := purgeLedgerReceiptPath(target, envelope.generation.Generation, envelope.checkpoint.TransactionID)
			expectedReceipts[receiptPath] = struct{}{}
			anchorBody, exists, err := readCanonicalBytesAt(canonical, envelope.anchor, receiptPath, canonicalPurgeReceiptMaxBytes)
			if err != nil {
				return result, err
			}
			if !exists {
				return result, fmt.Errorf("publication generation %d has no atomic purge receipt at anchor %s", envelope.generation.Generation, envelope.anchor)
			}
			finding, err := validateHistoricalPurgeReceipt(canonical, runtime, target, envelope, receiptPath, anchorBody)
			if err != nil {
				return result, err
			}
			if finding != nil {
				return result, fmt.Errorf("%s: %s", finding.Code, finding.Message)
			}
			headBody, headExists, err := readCanonicalBytesAt(canonical, head, receiptPath, canonicalPurgeReceiptMaxBytes)
			if err != nil {
				return result, err
			}
			if !headExists || !bytes.Equal(headBody, anchorBody) {
				if err := stageBody(receiptPath, anchorBody); err != nil {
					return result, err
				}
				result.Receipts++
			}
			if envelope.checkpoint.Schema == pub.CheckpointSchemaV1 {
				attestationPath := legacyPurgePlanAttestationPath(target, envelope.generation.Generation, envelope.checkpoint.TransactionID)
				expectedAttestations[attestationPath] = struct{}{}
				_, expectedBody, err := legacyPurgePlanAttestationForEnvelope(target, envelope, anchorBody)
				if err != nil {
					return result, err
				}
				actualBody, actualExists, err := readCanonicalBytesAt(canonical, head, attestationPath, legacyPurgeAttestationMaxBytes)
				if err != nil {
					return result, err
				}
				if !actualExists || !bytes.Equal(actualBody, expectedBody) {
					if err := stageBody(attestationPath, expectedBody); err != nil {
						return result, err
					}
					result.Attestations++
				}
			}
		}
		lastIdentity = identity
		lastClosureIdentity = closureIdentity
		lastEnvelope = envelope
		lastGeneration = envelope.generation.Generation
		publicationSeen = true
	}
	if publicationSeen {
		_, present, err := purgeLedgerEnvelopeIdentityAt(canonical, head, generationPath, checkpointPath, planPath)
		if err != nil {
			return result, err
		}
		if present != 3 {
			return result, errors.New("current publication control triplet is incomplete")
		}
	}
	for _, ledger := range []struct {
		prefix   string
		expected map[string]struct{}
	}{
		{prefix: remoteStatePath(target, "purges") + "/", expected: expectedReceipts},
		{prefix: remoteStatePath(target, "purge-migrations") + "/", expected: expectedAttestations},
	} {
		names, err := canonical.ListFilesAt(head, ledger.prefix)
		if err != nil {
			return result, err
		}
		for _, name := range names {
			if _, exists := ledger.expected[name]; !exists {
				return result, fmt.Errorf("canonical purge ledger has orphan evidence %s; additive repair will not delete it", name)
			}
		}
	}
	if len(staged) == 0 {
		result.Commit = head
		return result, nil
	}
	result.Commit, result.Changed, err = applyCanonicalState(ctx, canonical, "fsck-repair-purge-ledger", "sow fsck: repair canonical purge ledger for "+target, staged, nil, state.ApplyOptions{})
	if err != nil {
		return result, errors.Join(errPurgeLedgerRepairMutation, err)
	}
	return result, nil
}

func ensurePurgeLedgerRepairTransactionDir(stateDir, transactionDir string) error {
	stateAbs, err := filepath.Abs(stateDir)
	if err != nil {
		return err
	}
	txAbs, err := filepath.Abs(transactionDir)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(stateAbs, txAbs)
	if err != nil || relative == "." || relative == "" || relative == ".." || filepath.IsAbs(relative) || len(relative) >= 3 && relative[:3] == ".."+string(os.PathSeparator) {
		return errors.New("purge ledger repair staging directory must be below the state directory")
	}
	return nil
}
