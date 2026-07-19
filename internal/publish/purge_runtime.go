package publish

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

type purgeEvidenceBackend struct {
	vendor     string
	zoneID     string
	cloudflare CloudflarePurgeEvidenceProvider
	edgeOne    EdgeOnePurgeEvidenceProvider
}

func (p *Publisher) purgeEvidenceBackend() (purgeEvidenceBackend, bool) {
	switch driver := p.driver.(type) {
	case r2Driver:
		provider, ok := driver.provider.(CloudflarePurgeEvidenceProvider)
		if !ok {
			return purgeEvidenceBackend{}, false
		}
		zoneID := provider.CloudflarePurgeEvidenceZoneID()
		if !validPurgeEvidenceIdentifier(zoneID) {
			return purgeEvidenceBackend{}, false
		}
		return purgeEvidenceBackend{vendor: PurgeVendorCloudflare, zoneID: zoneID, cloudflare: provider}, true
	case cosDriver:
		provider, ok := driver.provider.(EdgeOnePurgeEvidenceProvider)
		if !ok {
			return purgeEvidenceBackend{}, false
		}
		zoneID := provider.EdgeOnePurgeEvidenceZoneID()
		if !validPurgeEvidenceIdentifier(zoneID) {
			return purgeEvidenceBackend{}, false
		}
		return purgeEvidenceBackend{vendor: PurgeVendorEdgeOne, zoneID: zoneID, edgeOne: provider}, true
	default:
		return purgeEvidenceBackend{}, false
	}
}

func (p *Publisher) requirePurgeEvidenceCapability(plan Plan) error {
	if !p.requirePurgeEvidence || len(plan.PurgeURLs) == 0 {
		return nil
	}
	if _, ok := p.purgeEvidenceBackend(); !ok {
		return fmt.Errorf("%w: target %s provider cannot produce durable purge evidence", ErrCapability, p.target)
	}
	return nil
}

// purgeAndRecord executes one exact URL closure through the receipt-bearing
// vendor API. The sidecar shares the outer publish-journal flock, so accepted
// EdgeOne jobs and completed batches are atomically recoverable without a
// second lock protocol. When force is false, a crash after the sidecar fsync
// but before PhasePurged reuses that completed proof; replayed mutable writes
// pass force=true and obtain a new attempt.
func (p *Publisher) purgeAndRecord(
	ctx context.Context,
	request Request,
	result *Result,
	generationSHA, planSHA, checkpointSHA string,
	urls []string,
	purpose PurgeAttemptPurpose,
	force bool,
) error {
	if len(urls) == 0 {
		return nil
	}
	if !p.requirePurgeEvidence {
		return p.driver.purge(ctx, urls)
	}
	backend, ok := p.purgeEvidenceBackend()
	if !ok {
		return fmt.Errorf("%w: target %s provider cannot produce durable purge evidence", ErrCapability, p.target)
	}
	fullURLs, err := canonicalPurgeURLs(request.Plan.PurgeURLs)
	if err != nil {
		return fmt.Errorf("canonical full purge closure: %w", err)
	}
	currentURLs, err := canonicalPurgeURLs(urls)
	if err != nil {
		return fmt.Errorf("canonical purge attempt: %w", err)
	}
	if purpose == PurgeAttemptDeletionRepair && !purgeURLSubset(fullURLs, currentURLs) {
		return errors.New("deletion-repair purge is outside the plan's exact closure")
	}
	store := purgeEvidenceStore{dir: p.journal.dir}
	evidence, _, path, err := store.loadOrCreate(PurgeEvidenceBinding{
		Target: p.target, TransactionID: request.TransactionID,
		Generation: request.Generation.Generation, GenerationSHA256: generationSHA,
		PlanSHA256: planSHA, CheckpointSHA256: checkpointSHA, URLs: fullURLs,
	})
	if err != nil {
		return fmt.Errorf("load purge evidence: %w", err)
	}
	if err := setPurgeEvidenceResult(result, path, evidence); err != nil {
		return err
	}

	attemptID, found := latestMatchingPurgeAttempt(evidence, purpose, currentURLs)
	if found {
		attempt := evidence.Attempts[attemptID-1]
		if purgeAttemptHasFailed(attempt) {
			found = false
		} else if purgeAttemptAllCompleted(attempt) {
			if err := validateCompletedPurgeAttempt(*evidence, attemptID, purpose, currentURLs, backend); err != nil {
				return err
			}
			if !force {
				return nil
			}
			found = false
		}
	}
	if !found {
		attemptID, err = store.beginAttempt(path, evidence, purpose, currentURLs)
		if err != nil {
			return fmt.Errorf("begin purge evidence attempt: %w", err)
		}
		if err := setPurgeEvidenceResult(result, path, evidence); err != nil {
			return err
		}
	}

	for batchIndex, start := 0, 0; start < len(currentURLs); batchIndex, start = batchIndex+1, start+purgeEvidenceBatchMaxURLs {
		end := min(start+purgeEvidenceBatchMaxURLs, len(currentURLs))
		batchURLs := currentURLs[start:end]
		existing, exists := purgeAttemptBatch(evidence, attemptID, batchIndex)
		if exists {
			if err := validatePurgeReceiptBinding(existing, batchIndex, batchURLs, backend); err != nil {
				return err
			}
			if existing.Status == PurgeReceiptCompleted {
				continue
			}
			if existing.Status == PurgeReceiptFailed {
				return errors.New("failed purge attempt cannot be resumed")
			}
		}

		if backend.cloudflare != nil {
			if exists {
				return errors.New("Cloudflare purge evidence cannot remain accepted asynchronously")
			}
			receipt, callErr := backend.cloudflare.CloudflarePurgeBatchEvidence(ctx, batchURLs)
			if callErr != nil {
				return callErr
			}
			receipt.BatchIndex = batchIndex
			if err := validatePurgeReceiptBinding(receipt, batchIndex, batchURLs, backend); err != nil {
				return err
			}
			if receipt.Status != PurgeReceiptCompleted {
				return errors.New("Cloudflare purge API returned a non-completed receipt")
			}
			if err := store.persistBatchCompleted(path, evidence, attemptID, batchURLs, receipt); err != nil {
				return fmt.Errorf("persist Cloudflare purge receipt: %w", err)
			}
		} else {
			accepted := existing
			if !exists {
				accepted, err = backend.edgeOne.EdgeOneAcceptPurgeBatch(ctx, batchURLs)
				if err != nil {
					return err
				}
				accepted.BatchIndex = batchIndex
				if err := validatePurgeReceiptBinding(accepted, batchIndex, batchURLs, backend); err != nil {
					return err
				}
				if accepted.Status != PurgeReceiptAccepted {
					return errors.New("EdgeOne purge API did not return an accepted receipt")
				}
				if err := store.persistBatchAccepted(path, evidence, attemptID, batchURLs, accepted); err != nil {
					return fmt.Errorf("persist accepted EdgeOne purge receipt: %w", err)
				}
				if err := setPurgeEvidenceResult(result, path, evidence); err != nil {
					return err
				}
			}
			terminal, completeErr := backend.edgeOne.EdgeOneCompletePurgeBatch(ctx, accepted)
			terminal.BatchIndex = batchIndex
			if completeErr != nil {
				if terminal.Status == PurgeReceiptFailed || terminal.Status == PurgeReceiptIndeterminate || terminal.Status == PurgeReceiptAccepted && terminal != accepted {
					if err := validatePurgeReceiptBinding(terminal, batchIndex, batchURLs, backend); err != nil {
						return errors.Join(completeErr, err)
					}
					var persistErr error
					switch terminal.Status {
					case PurgeReceiptFailed:
						persistErr = store.persistBatchFailed(path, evidence, attemptID, batchURLs, terminal)
					case PurgeReceiptIndeterminate:
						persistErr = store.persistBatchIndeterminate(path, evidence, attemptID, batchURLs, terminal)
					case PurgeReceiptAccepted:
						persistErr = store.persistBatchAccepted(path, evidence, attemptID, batchURLs, terminal)
					}
					if persistErr != nil {
						return errors.Join(completeErr, fmt.Errorf("persist EdgeOne purge status receipt: %w", persistErr))
					}
					if err := setPurgeEvidenceResult(result, path, evidence); err != nil {
						return errors.Join(completeErr, err)
					}
				}
				return completeErr
			}
			if err := validatePurgeReceiptBinding(terminal, batchIndex, batchURLs, backend); err != nil {
				return err
			}
			if terminal.Status != PurgeReceiptCompleted {
				return errors.New("EdgeOne purge status API returned a non-completed receipt")
			}
			if err := store.persistBatchCompleted(path, evidence, attemptID, batchURLs, terminal); err != nil {
				return fmt.Errorf("persist completed EdgeOne purge receipt: %w", err)
			}
		}
		if err := setPurgeEvidenceResult(result, path, evidence); err != nil {
			return err
		}
	}
	if err := validateCompletedPurgeAttempt(*evidence, attemptID, purpose, currentURLs, backend); err != nil {
		return err
	}
	return setPurgeEvidenceResult(result, path, evidence)
}

func latestMatchingPurgeAttempt(evidence *PurgeEvidence, purpose PurgeAttemptPurpose, urls []string) (uint64, bool) {
	if evidence == nil {
		return 0, false
	}
	digest, err := PurgeURLsDigest(urls)
	if err != nil {
		return 0, false
	}
	for index := len(evidence.Attempts) - 1; index >= 0; index-- {
		attempt := evidence.Attempts[index]
		if attempt.Purpose == purpose && attempt.URLCount == len(urls) && attempt.URLsSHA256 == digest {
			return attempt.ID, true
		}
	}
	return 0, false
}

func purgeAttemptBatch(evidence *PurgeEvidence, attemptID uint64, batchIndex int) (PurgeReceipt, bool) {
	if evidence == nil || attemptID == 0 || attemptID > uint64(len(evidence.Attempts)) {
		return PurgeReceipt{}, false
	}
	batches := evidence.Attempts[attemptID-1].Batches
	index := sort.Search(len(batches), func(index int) bool { return batches[index].BatchIndex >= batchIndex })
	if index == len(batches) || batches[index].BatchIndex != batchIndex {
		return PurgeReceipt{}, false
	}
	return batches[index], true
}

func purgeAttemptHasFailed(attempt PurgeAttempt) bool {
	for _, receipt := range attempt.Batches {
		if receipt.Status == PurgeReceiptFailed || receipt.Status == PurgeReceiptIndeterminate {
			return true
		}
	}
	return false
}

func purgeAttemptAllCompleted(attempt PurgeAttempt) bool {
	want := (attempt.URLCount + purgeEvidenceBatchMaxURLs - 1) / purgeEvidenceBatchMaxURLs
	if len(attempt.Batches) != want {
		return false
	}
	for index, receipt := range attempt.Batches {
		if receipt.BatchIndex != index || receipt.Status != PurgeReceiptCompleted {
			return false
		}
	}
	return true
}

func validateCompletedPurgeAttempt(evidence PurgeEvidence, attemptID uint64, purpose PurgeAttemptPurpose, urls []string, backend purgeEvidenceBackend) error {
	if purpose == PurgeAttemptFull {
		if err := evidence.ValidateFullClosure(attemptID, urls); err != nil {
			return err
		}
	}
	if attemptID == 0 || attemptID > uint64(len(evidence.Attempts)) {
		return errors.New("purge closure names an unknown attempt")
	}
	attempt := evidence.Attempts[attemptID-1]
	digest, err := PurgeURLsDigest(urls)
	if err != nil {
		return err
	}
	if attempt.Purpose != purpose || attempt.URLCount != len(urls) || attempt.URLsSHA256 != digest || !purgeAttemptAllCompleted(attempt) {
		return errors.New("purge attempt does not complete the exact requested closure")
	}
	for index, start := 0, 0; start < len(urls); index, start = index+1, start+purgeEvidenceBatchMaxURLs {
		end := min(start+purgeEvidenceBatchMaxURLs, len(urls))
		if err := validatePurgeReceiptBinding(attempt.Batches[index], index, urls[start:end], backend); err != nil {
			return err
		}
	}
	return nil
}

func validatePurgeReceiptBinding(receipt PurgeReceipt, batchIndex int, urls []string, backend purgeEvidenceBackend) error {
	digest, err := PurgeURLsDigest(urls)
	if err != nil {
		return err
	}
	if receipt.BatchIndex != batchIndex || receipt.URLCount != len(urls) || receipt.URLsSHA256 != digest ||
		receipt.Vendor != backend.vendor || receipt.ZoneID != backend.zoneID {
		return errors.New("purge receipt differs from the exact provider batch binding")
	}
	return nil
}

func setPurgeEvidenceResult(result *Result, path string, evidence *PurgeEvidence) error {
	if result == nil || evidence == nil {
		return errors.New("nil purge evidence result")
	}
	digest, err := evidence.Digest()
	if err != nil {
		return err
	}
	result.PurgeEvidencePath = path
	result.PurgeEvidenceSHA256 = digest
	return nil
}

func purgeURLSubset(full, subset []string) bool {
	fullIndex := 0
	for _, value := range subset {
		for fullIndex < len(full) && full[fullIndex] < value {
			fullIndex++
		}
		if fullIndex == len(full) || full[fullIndex] != value {
			return false
		}
	}
	return true
}
