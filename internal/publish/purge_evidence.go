package publish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	PurgeEvidenceSchema       = "sow-purge-evidence/v1"
	purgeEvidenceMaxBytes     = 4 << 20
	purgeEvidenceBatchMaxURLs = 100
)

type PurgeAttemptPurpose string

const (
	PurgeAttemptFull           PurgeAttemptPurpose = "full"
	PurgeAttemptDeletionRepair PurgeAttemptPurpose = "deletion-repair"
)

func (p PurgeAttemptPurpose) validate() error {
	switch p {
	case PurgeAttemptFull, PurgeAttemptDeletionRepair:
		return nil
	default:
		return fmt.Errorf("invalid purge attempt purpose %q", p)
	}
}

type PurgeReceiptStatus string

const (
	PurgeReceiptAccepted  PurgeReceiptStatus = "accepted"
	PurgeReceiptCompleted PurgeReceiptStatus = "completed"
	PurgeReceiptFailed    PurgeReceiptStatus = "failed"
	// PurgeReceiptIndeterminate means the provider accepted a durable job ID,
	// but repeated exact job-id queries across separate recovery attempts no
	// longer returned that job. Replaying the same bounded URL closure is safe,
	// while pretending that the vanished job completed is not.
	PurgeReceiptIndeterminate PurgeReceiptStatus = "indeterminate"

	PurgeVendorCloudflare = "cloudflare"
	PurgeVendorEdgeOne    = "edgeone"
)

// PurgeReceipt is the durable provider response for one exact, bounded URL
// batch. ObservedAt values are local UTC observations of provider responses;
// they do not claim that every edge PoP had converged at that instant.
type PurgeReceipt struct {
	BatchIndex              int                `json:"batch_index"`
	URLCount                int                `json:"url_count"`
	URLsSHA256              string             `json:"urls_sha256"`
	Vendor                  string             `json:"vendor"`
	ZoneID                  string             `json:"zone_id"`
	Status                  PurgeReceiptStatus `json:"status"`
	JobID                   string             `json:"job_id,omitempty"`
	AcceptedRequestID       string             `json:"accepted_request_id"`
	AcceptedObservedAt      string             `json:"accepted_observed_at"`
	CompletedRequestID      string             `json:"completed_request_id,omitempty"`
	CompletedObservedAt     string             `json:"completed_observed_at,omitempty"`
	FailedRequestID         string             `json:"failed_request_id,omitempty"`
	FailedObservedAt        string             `json:"failed_observed_at,omitempty"`
	VendorResultID          string             `json:"vendor_result_id,omitempty"`
	ProviderCreatedAt       string             `json:"provider_created_at,omitempty"`
	ProviderUpdatedAt       string             `json:"provider_updated_at,omitempty"`
	NotFoundConfirmations   uint32             `json:"not_found_confirmations,omitempty"`
	FirstNotFoundRequestID  string             `json:"first_not_found_request_id,omitempty"`
	FirstNotFoundObservedAt string             `json:"first_not_found_observed_at,omitempty"`
	LastNotFoundRequestID   string             `json:"last_not_found_request_id,omitempty"`
	LastNotFoundObservedAt  string             `json:"last_not_found_observed_at,omitempty"`
	IndeterminateRequestID  string             `json:"indeterminate_request_id,omitempty"`
	IndeterminateObservedAt string             `json:"indeterminate_observed_at,omitempty"`
}

type PurgeAttempt struct {
	ID         uint64              `json:"id"`
	Purpose    PurgeAttemptPurpose `json:"purpose"`
	URLCount   int                 `json:"url_count"`
	URLsSHA256 string              `json:"urls_sha256"`
	Batches    []PurgeReceipt      `json:"batches"`
	StartedAt  string              `json:"started_at"`
	UpdatedAt  string              `json:"updated_at"`
}

// PurgeEvidence binds provider receipts to the immutable publication request.
// It is a local recovery sidecar first and is suitable for copying into the
// canonical Git state after the corresponding remote checkpoint commits.
type PurgeEvidence struct {
	Schema           string         `json:"schema"`
	Target           TargetName     `json:"target"`
	TransactionID    string         `json:"transaction_id"`
	Generation       uint64         `json:"generation"`
	GenerationSHA256 string         `json:"generation_sha256"`
	PlanSHA256       string         `json:"plan_sha256"`
	CheckpointSHA256 string         `json:"checkpoint_sha256"`
	URLCount         int            `json:"url_count"`
	URLsSHA256       string         `json:"urls_sha256"`
	Attempts         []PurgeAttempt `json:"attempts"`
	CreatedAt        string         `json:"created_at"`
	UpdatedAt        string         `json:"updated_at"`
}

type PurgeEvidenceBinding struct {
	Target           TargetName
	TransactionID    string
	Generation       uint64
	GenerationSHA256 string
	PlanSHA256       string
	CheckpointSHA256 string
	URLs             []string
}

type purgeEvidenceStore struct {
	dir string
	now func() time.Time
}

// PurgeURLsDigest canonicalizes an exact URL set by sorting it and rejecting
// duplicates, then hashes its canonical JSON array representation.
func PurgeURLsDigest(urls []string) (string, error) {
	canonical, err := canonicalPurgeURLs(urls)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalPurgeURLs(urls []string) ([]string, error) {
	if len(urls) == 0 {
		return nil, errors.New("purge URL set is empty")
	}
	canonical := append([]string(nil), urls...)
	for _, value := range canonical {
		if value == "" || value != strings.TrimSpace(value) || len(value) > 16<<10 || strings.ContainsAny(value, "\x00\r\n\t") {
			return nil, errors.New("purge URL set contains an unsafe URL")
		}
	}
	sort.Strings(canonical)
	for index := 1; index < len(canonical); index++ {
		if canonical[index] == canonical[index-1] {
			return nil, errors.New("purge URL set contains a duplicate URL")
		}
	}
	return canonical, nil
}

func (binding PurgeEvidenceBinding) validate() (string, int, error) {
	if err := binding.Target.Validate(); err != nil {
		return "", 0, err
	}
	if !transactionIDPat.MatchString(binding.TransactionID) || binding.Generation == 0 ||
		!hexSHA256Pattern.MatchString(binding.GenerationSHA256) ||
		!hexSHA256Pattern.MatchString(binding.PlanSHA256) ||
		!hexSHA256Pattern.MatchString(binding.CheckpointSHA256) {
		return "", 0, errors.New("invalid purge evidence binding")
	}
	digest, err := PurgeURLsDigest(binding.URLs)
	return digest, len(binding.URLs), err
}

func (s purgeEvidenceStore) path(target TargetName, transactionID string) (string, error) {
	if err := target.Validate(); err != nil {
		return "", err
	}
	if !transactionIDPat.MatchString(transactionID) {
		return "", errors.New("invalid publish transaction ID")
	}
	if s.dir == "" {
		return "", errors.New("publish journal directory is required")
	}
	return filepath.Join(s.dir, fmt.Sprintf("%s-%s.purge.json", target, transactionID)), nil
}

func (s purgeEvidenceStore) ensureDirectory() error {
	return journalStore{dir: s.dir}.ensureDirectory()
}

func (s purgeEvidenceStore) timestamp() string {
	now := s.now
	if now == nil {
		now = time.Now
	}
	return now().UTC().Format(time.RFC3339Nano)
}

func (s purgeEvidenceStore) loadOrCreate(binding PurgeEvidenceBinding) (*PurgeEvidence, bool, string, error) {
	digest, count, err := binding.validate()
	if err != nil {
		return nil, false, "", err
	}
	if err := s.ensureDirectory(); err != nil {
		return nil, false, "", fmt.Errorf("%w: prepare purge evidence directory: %v", ErrJournalConflict, err)
	}
	path, err := s.path(binding.Target, binding.TransactionID)
	if err != nil {
		return nil, false, "", err
	}
	body, err := readPurgeEvidenceFile(path)
	if err == nil {
		evidence, decodeErr := DecodePurgeEvidence(body)
		if decodeErr != nil {
			return nil, false, path, fmt.Errorf("%w: decode existing purge evidence: %v", ErrJournalConflict, decodeErr)
		}
		if evidence.Target != binding.Target || evidence.TransactionID != binding.TransactionID ||
			evidence.Generation != binding.Generation || evidence.GenerationSHA256 != binding.GenerationSHA256 ||
			evidence.PlanSHA256 != binding.PlanSHA256 || evidence.CheckpointSHA256 != binding.CheckpointSHA256 ||
			evidence.URLCount != count || evidence.URLsSHA256 != digest {
			return nil, false, path, fmt.Errorf("%w: existing purge evidence binding changed", ErrJournalConflict)
		}
		return &evidence, false, path, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, path, fmt.Errorf("%w: read existing purge evidence: %v", ErrJournalConflict, err)
	}
	stamp := s.timestamp()
	evidence := PurgeEvidence{
		Schema: PurgeEvidenceSchema, Target: binding.Target, TransactionID: binding.TransactionID,
		Generation: binding.Generation, GenerationSHA256: binding.GenerationSHA256,
		PlanSHA256: binding.PlanSHA256, CheckpointSHA256: binding.CheckpointSHA256,
		URLCount: count, URLsSHA256: digest, Attempts: []PurgeAttempt{},
		CreatedAt: stamp, UpdatedAt: stamp,
	}
	if err := s.write(path, evidence); err != nil {
		return nil, false, path, fmt.Errorf("%w: create purge evidence: %v", ErrJournalConflict, err)
	}
	return &evidence, true, path, nil
}

func (s purgeEvidenceStore) beginAttempt(path string, evidence *PurgeEvidence, purpose PurgeAttemptPurpose, urls []string) (uint64, error) {
	if evidence == nil {
		return 0, errors.New("nil purge evidence")
	}
	if err := purpose.validate(); err != nil {
		return 0, err
	}
	canonical, err := canonicalPurgeURLs(urls)
	if err != nil {
		return 0, err
	}
	digest, err := PurgeURLsDigest(canonical)
	if err != nil {
		return 0, err
	}
	count := len(canonical)
	if purpose == PurgeAttemptFull && (count != evidence.URLCount || digest != evidence.URLsSHA256) {
		return 0, errors.New("full purge attempt differs from the bound URL closure")
	}
	if purpose == PurgeAttemptDeletionRepair && count > evidence.URLCount {
		return 0, errors.New("deletion repair exceeds the bound URL closure")
	}
	next := clonePurgeEvidence(*evidence)
	id := uint64(len(next.Attempts) + 1)
	stamp := s.timestamp()
	next.Attempts = append(next.Attempts, PurgeAttempt{
		ID: id, Purpose: purpose, URLCount: count, URLsSHA256: digest,
		Batches: []PurgeReceipt{}, StartedAt: stamp, UpdatedAt: stamp,
	})
	next.UpdatedAt = stamp
	if err := s.writeBound(path, next); err != nil {
		return 0, err
	}
	*evidence = next
	return id, nil
}

func (s purgeEvidenceStore) persistBatchAccepted(path string, evidence *PurgeEvidence, attemptID uint64, batchURLs []string, receipt PurgeReceipt) error {
	return s.persistBatch(path, evidence, attemptID, batchURLs, receipt, PurgeReceiptAccepted)
}

func (s purgeEvidenceStore) persistBatchCompleted(path string, evidence *PurgeEvidence, attemptID uint64, batchURLs []string, receipt PurgeReceipt) error {
	return s.persistBatch(path, evidence, attemptID, batchURLs, receipt, PurgeReceiptCompleted)
}

func (s purgeEvidenceStore) persistBatchFailed(path string, evidence *PurgeEvidence, attemptID uint64, batchURLs []string, receipt PurgeReceipt) error {
	return s.persistBatch(path, evidence, attemptID, batchURLs, receipt, PurgeReceiptFailed)
}

func (s purgeEvidenceStore) persistBatchIndeterminate(path string, evidence *PurgeEvidence, attemptID uint64, batchURLs []string, receipt PurgeReceipt) error {
	return s.persistBatch(path, evidence, attemptID, batchURLs, receipt, PurgeReceiptIndeterminate)
}

func (s purgeEvidenceStore) persistBatch(path string, evidence *PurgeEvidence, attemptID uint64, batchURLs []string, receipt PurgeReceipt, wanted PurgeReceiptStatus) error {
	if evidence == nil {
		return errors.New("nil purge evidence")
	}
	if receipt.Status != wanted {
		return fmt.Errorf("purge receipt status=%q, want %q", receipt.Status, wanted)
	}
	canonical, err := canonicalPurgeURLs(batchURLs)
	if err != nil {
		return err
	}
	digest, err := PurgeURLsDigest(canonical)
	if err != nil {
		return err
	}
	count := len(canonical)
	if receipt.URLCount != count || receipt.URLsSHA256 != digest {
		return errors.New("purge receipt differs from the exact batch URL closure")
	}
	next := clonePurgeEvidence(*evidence)
	attemptIndex := sort.Search(len(next.Attempts), func(index int) bool { return next.Attempts[index].ID >= attemptID })
	if attemptIndex == len(next.Attempts) || next.Attempts[attemptIndex].ID != attemptID {
		return errors.New("purge receipt names an unknown attempt")
	}
	attempt := &next.Attempts[attemptIndex]
	maximumBatches := (attempt.URLCount + purgeEvidenceBatchMaxURLs - 1) / purgeEvidenceBatchMaxURLs
	if receipt.BatchIndex < 0 || receipt.BatchIndex >= maximumBatches {
		return errors.New("purge receipt batch index is outside its attempt")
	}
	batchIndex := sort.Search(len(attempt.Batches), func(index int) bool { return attempt.Batches[index].BatchIndex >= receipt.BatchIndex })
	if batchIndex < len(attempt.Batches) && attempt.Batches[batchIndex].BatchIndex == receipt.BatchIndex {
		merged, mergeErr := mergePurgeReceipt(attempt.Batches[batchIndex], receipt)
		if mergeErr != nil {
			return mergeErr
		}
		attempt.Batches[batchIndex] = merged
	} else {
		if receipt.Status == PurgeReceiptFailed || receipt.Status == PurgeReceiptIndeterminate {
			return errors.New("failed purge receipt has no durable acceptance")
		}
		attempt.Batches = append(attempt.Batches, PurgeReceipt{})
		copy(attempt.Batches[batchIndex+1:], attempt.Batches[batchIndex:])
		attempt.Batches[batchIndex] = receipt
	}
	stamp := s.timestamp()
	attempt.UpdatedAt = stamp
	next.UpdatedAt = stamp
	if err := s.writeBound(path, next); err != nil {
		return err
	}
	*evidence = next
	return nil
}

func mergePurgeReceipt(existing, incoming PurgeReceipt) (PurgeReceipt, error) {
	if existing.BatchIndex != incoming.BatchIndex || existing.URLCount != incoming.URLCount || existing.URLsSHA256 != incoming.URLsSHA256 ||
		existing.Vendor != incoming.Vendor || existing.ZoneID != incoming.ZoneID || existing.JobID != incoming.JobID ||
		existing.AcceptedRequestID != incoming.AcceptedRequestID || existing.AcceptedObservedAt != incoming.AcceptedObservedAt ||
		existing.VendorResultID != incoming.VendorResultID ||
		existing.ProviderCreatedAt != "" && existing.ProviderCreatedAt != incoming.ProviderCreatedAt ||
		existing.ProviderUpdatedAt != "" && existing.ProviderUpdatedAt != incoming.ProviderUpdatedAt {
		return PurgeReceipt{}, errors.New("purge receipt changed its durable acceptance identity")
	}
	if existing.Status == incoming.Status {
		if existing.Status == PurgeReceiptAccepted && validAcceptedNotFoundAdvance(existing, incoming) {
			return incoming, nil
		}
		if existing != incoming {
			return PurgeReceipt{}, errors.New("purge receipt rewrote a durable response")
		}
		return existing, nil
	}
	if existing.Status != PurgeReceiptAccepted || incoming.Status != PurgeReceiptCompleted && incoming.Status != PurgeReceiptFailed && incoming.Status != PurgeReceiptIndeterminate {
		return PurgeReceipt{}, errors.New("purge receipt attempted an invalid status transition")
	}
	if incoming.Status == PurgeReceiptIndeterminate {
		if !validIndeterminateNotFoundAdvance(existing, incoming) {
			return PurgeReceipt{}, errors.New("indeterminate purge receipt did not extend the accepted not-found history")
		}
	} else if !samePurgeNotFoundHistory(existing, incoming) {
		return PurgeReceipt{}, errors.New("terminal purge receipt rewrote the accepted not-found history")
	}
	return incoming, nil
}

func validAcceptedNotFoundAdvance(existing, incoming PurgeReceipt) bool {
	if incoming.NotFoundConfirmations != existing.NotFoundConfirmations+1 || incoming.NotFoundConfirmations == 0 ||
		incoming.FirstNotFoundRequestID == "" || incoming.FirstNotFoundObservedAt == "" ||
		incoming.LastNotFoundRequestID == "" || incoming.LastNotFoundObservedAt == "" ||
		incoming.IndeterminateRequestID != "" || incoming.IndeterminateObservedAt != "" {
		return false
	}
	if existing.NotFoundConfirmations == 0 {
		return incoming.FirstNotFoundRequestID == incoming.LastNotFoundRequestID && incoming.FirstNotFoundObservedAt == incoming.LastNotFoundObservedAt
	}
	previousLast, previousErr := time.Parse(time.RFC3339Nano, existing.LastNotFoundObservedAt)
	incomingLast, incomingErr := time.Parse(time.RFC3339Nano, incoming.LastNotFoundObservedAt)
	return previousErr == nil && incomingErr == nil && !incomingLast.Before(previousLast) &&
		incoming.LastNotFoundRequestID != existing.LastNotFoundRequestID &&
		incoming.FirstNotFoundRequestID == existing.FirstNotFoundRequestID &&
		incoming.FirstNotFoundObservedAt == existing.FirstNotFoundObservedAt
}

func validIndeterminateNotFoundAdvance(existing, incoming PurgeReceipt) bool {
	copyIncoming := incoming
	copyIncoming.Status = PurgeReceiptAccepted
	copyIncoming.IndeterminateRequestID = ""
	copyIncoming.IndeterminateObservedAt = ""
	return validAcceptedNotFoundAdvance(existing, copyIncoming) &&
		incoming.IndeterminateRequestID == incoming.LastNotFoundRequestID &&
		incoming.IndeterminateObservedAt == incoming.LastNotFoundObservedAt
}

func samePurgeNotFoundHistory(left, right PurgeReceipt) bool {
	return left.NotFoundConfirmations == right.NotFoundConfirmations &&
		left.FirstNotFoundRequestID == right.FirstNotFoundRequestID &&
		left.FirstNotFoundObservedAt == right.FirstNotFoundObservedAt &&
		left.LastNotFoundRequestID == right.LastNotFoundRequestID &&
		left.LastNotFoundObservedAt == right.LastNotFoundObservedAt
}

// ValidateFullClosure proves that one full attempt contains a completed
// receipt for every deterministic provider batch of the exact bound URL set.
func (e PurgeEvidence) ValidateFullClosure(attemptID uint64, fullURLs []string) error {
	canonical, err := canonicalPurgeURLs(fullURLs)
	if err != nil {
		return err
	}
	digest, err := PurgeURLsDigest(canonical)
	if err != nil {
		return err
	}
	count := len(canonical)
	if e.URLCount != count || e.URLsSHA256 != digest {
		return errors.New("purge evidence is not bound to the requested full closure")
	}
	index := sort.Search(len(e.Attempts), func(index int) bool { return e.Attempts[index].ID >= attemptID })
	if index == len(e.Attempts) || e.Attempts[index].ID != attemptID {
		return errors.New("full closure names an unknown purge attempt")
	}
	attempt := e.Attempts[index]
	if attempt.Purpose != PurgeAttemptFull || attempt.URLCount != count || attempt.URLsSHA256 != digest {
		return errors.New("purge attempt is not the exact full closure")
	}
	expectedBatches := (len(canonical) + purgeEvidenceBatchMaxURLs - 1) / purgeEvidenceBatchMaxURLs
	if len(attempt.Batches) != expectedBatches {
		return errors.New("full purge attempt does not cover every batch")
	}
	var vendor, zoneID string
	for batchIndex := 0; batchIndex < expectedBatches; batchIndex++ {
		start := batchIndex * purgeEvidenceBatchMaxURLs
		end := min(start+purgeEvidenceBatchMaxURLs, len(canonical))
		batchURLs := canonical[start:end]
		batchDigest, digestErr := PurgeURLsDigest(batchURLs)
		if digestErr != nil {
			return digestErr
		}
		batchCount := len(batchURLs)
		receipt := attempt.Batches[batchIndex]
		if receipt.BatchIndex != batchIndex || receipt.URLCount != batchCount || receipt.URLsSHA256 != batchDigest || receipt.Status != PurgeReceiptCompleted {
			return fmt.Errorf("purge batch %d is not completed for the exact URL closure", batchIndex)
		}
		if batchIndex == 0 {
			vendor, zoneID = receipt.Vendor, receipt.ZoneID
		} else if receipt.Vendor != vendor || receipt.ZoneID != zoneID {
			return errors.New("full purge attempt crossed provider or zone identities")
		}
	}
	return nil
}

func validateFullClosure(evidence *PurgeEvidence, attemptID uint64, fullURLs []string) error {
	if evidence == nil {
		return errors.New("nil purge evidence")
	}
	return evidence.ValidateFullClosure(attemptID, fullURLs)
}

func (e PurgeEvidence) Canonical() ([]byte, error) {
	copyEvidence := clonePurgeEvidence(e)
	if copyEvidence.Attempts == nil {
		copyEvidence.Attempts = []PurgeAttempt{}
	}
	sort.Slice(copyEvidence.Attempts, func(i, j int) bool { return copyEvidence.Attempts[i].ID < copyEvidence.Attempts[j].ID })
	for index := range copyEvidence.Attempts {
		if copyEvidence.Attempts[index].Batches == nil {
			copyEvidence.Attempts[index].Batches = []PurgeReceipt{}
		}
		sort.Slice(copyEvidence.Attempts[index].Batches, func(i, j int) bool {
			return copyEvidence.Attempts[index].Batches[i].BatchIndex < copyEvidence.Attempts[index].Batches[j].BatchIndex
		})
	}
	if err := copyEvidence.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(copyEvidence)
}

func (e PurgeEvidence) Digest() (string, error) {
	body, err := e.Canonical()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func (e PurgeEvidence) validate() error {
	if e.Schema != PurgeEvidenceSchema || e.Target.Validate() != nil || !transactionIDPat.MatchString(e.TransactionID) || e.Generation == 0 ||
		!hexSHA256Pattern.MatchString(e.GenerationSHA256) || !hexSHA256Pattern.MatchString(e.PlanSHA256) || !hexSHA256Pattern.MatchString(e.CheckpointSHA256) ||
		e.URLCount <= 0 || !hexSHA256Pattern.MatchString(e.URLsSHA256) || !isCanonicalUTCTime(e.CreatedAt) || !isCanonicalUTCTime(e.UpdatedAt) {
		return errors.New("invalid purge evidence envelope")
	}
	createdAt, _ := time.Parse(time.RFC3339Nano, e.CreatedAt)
	updatedAt, _ := time.Parse(time.RFC3339Nano, e.UpdatedAt)
	if updatedAt.Before(createdAt) {
		return errors.New("purge evidence update precedes creation")
	}
	for index, attempt := range e.Attempts {
		if attempt.ID != uint64(index+1) || attempt.Purpose.validate() != nil || attempt.URLCount <= 0 || attempt.URLCount > e.URLCount ||
			!hexSHA256Pattern.MatchString(attempt.URLsSHA256) || !isCanonicalUTCTime(attempt.StartedAt) || !isCanonicalUTCTime(attempt.UpdatedAt) {
			return errors.New("invalid purge attempt")
		}
		startedAt, _ := time.Parse(time.RFC3339Nano, attempt.StartedAt)
		attemptUpdatedAt, _ := time.Parse(time.RFC3339Nano, attempt.UpdatedAt)
		if attemptUpdatedAt.Before(startedAt) || updatedAt.Before(attemptUpdatedAt) {
			return errors.New("invalid purge attempt timeline")
		}
		for batchIndex, receipt := range attempt.Batches {
			if batchIndex != 0 && attempt.Batches[batchIndex-1].BatchIndex >= receipt.BatchIndex {
				return errors.New("purge batches are not strictly ordered")
			}
			if err := receipt.validate(attempt); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r PurgeReceipt) validate(attempt PurgeAttempt) error {
	maximumBatches := (attempt.URLCount + purgeEvidenceBatchMaxURLs - 1) / purgeEvidenceBatchMaxURLs
	if r.BatchIndex < 0 || r.BatchIndex >= maximumBatches || r.URLCount <= 0 || r.URLCount > purgeEvidenceBatchMaxURLs || !hexSHA256Pattern.MatchString(r.URLsSHA256) ||
		(r.Vendor != PurgeVendorCloudflare && r.Vendor != PurgeVendorEdgeOne) || !safePurgeEvidenceText(r.ZoneID, 4096) ||
		!safePurgeEvidenceText(r.AcceptedRequestID, 4096) || !isCanonicalUTCTime(r.AcceptedObservedAt) ||
		!optionalPurgeEvidenceText(r.JobID, 4096) || !optionalPurgeEvidenceText(r.VendorResultID, 4096) {
		return errors.New("invalid purge batch receipt")
	}
	if r.Vendor == PurgeVendorCloudflare && (r.JobID != "" || r.VendorResultID == "") {
		return errors.New("invalid Cloudflare purge receipt")
	}
	if r.Vendor == PurgeVendorEdgeOne && r.JobID == "" {
		return errors.New("invalid EdgeOne purge receipt")
	}
	if !optionalPurgeEvidenceText(r.ProviderCreatedAt, 256) || !optionalPurgeEvidenceText(r.ProviderUpdatedAt, 256) {
		return errors.New("invalid provider purge timestamp")
	}
	acceptedAt, _ := time.Parse(time.RFC3339Nano, r.AcceptedObservedAt)
	if err := validatePurgeNotFoundEvidence(r, acceptedAt); err != nil {
		return err
	}
	switch r.Status {
	case PurgeReceiptAccepted:
		if r.CompletedRequestID != "" || r.CompletedObservedAt != "" || r.FailedRequestID != "" || r.FailedObservedAt != "" || r.IndeterminateRequestID != "" || r.IndeterminateObservedAt != "" {
			return errors.New("accepted purge receipt contains a terminal response")
		}
	case PurgeReceiptCompleted:
		if !safePurgeEvidenceText(r.CompletedRequestID, 4096) || !isCanonicalUTCTime(r.CompletedObservedAt) || r.FailedRequestID != "" || r.FailedObservedAt != "" || r.IndeterminateRequestID != "" || r.IndeterminateObservedAt != "" {
			return errors.New("completed purge receipt is incomplete")
		}
		completedAt, _ := time.Parse(time.RFC3339Nano, r.CompletedObservedAt)
		if completedAt.Before(acceptedAt) {
			return errors.New("purge completion precedes acceptance")
		}
	case PurgeReceiptFailed:
		if !safePurgeEvidenceText(r.FailedRequestID, 4096) || !isCanonicalUTCTime(r.FailedObservedAt) || r.CompletedRequestID != "" || r.CompletedObservedAt != "" || r.IndeterminateRequestID != "" || r.IndeterminateObservedAt != "" {
			return errors.New("failed purge receipt is incomplete")
		}
		failedAt, _ := time.Parse(time.RFC3339Nano, r.FailedObservedAt)
		if failedAt.Before(acceptedAt) {
			return errors.New("purge failure precedes acceptance")
		}
	case PurgeReceiptIndeterminate:
		if r.NotFoundConfirmations < 2 || !safePurgeEvidenceText(r.IndeterminateRequestID, 4096) || !isCanonicalUTCTime(r.IndeterminateObservedAt) ||
			r.CompletedRequestID != "" || r.CompletedObservedAt != "" || r.FailedRequestID != "" || r.FailedObservedAt != "" ||
			r.IndeterminateRequestID != r.LastNotFoundRequestID || r.IndeterminateObservedAt != r.LastNotFoundObservedAt {
			return errors.New("indeterminate purge receipt is incomplete")
		}
	default:
		return errors.New("invalid purge receipt status")
	}
	return nil
}

func validatePurgeNotFoundEvidence(r PurgeReceipt, acceptedAt time.Time) error {
	if r.NotFoundConfirmations > 1024 {
		return errors.New("purge receipt has too many not-found confirmations")
	}
	if r.NotFoundConfirmations == 0 {
		if r.FirstNotFoundRequestID != "" || r.FirstNotFoundObservedAt != "" || r.LastNotFoundRequestID != "" || r.LastNotFoundObservedAt != "" {
			return errors.New("purge receipt has uncounted not-found evidence")
		}
		return nil
	}
	if r.Vendor != PurgeVendorEdgeOne || !safePurgeEvidenceText(r.FirstNotFoundRequestID, 4096) || !safePurgeEvidenceText(r.LastNotFoundRequestID, 4096) ||
		!isCanonicalUTCTime(r.FirstNotFoundObservedAt) || !isCanonicalUTCTime(r.LastNotFoundObservedAt) {
		return errors.New("purge receipt has invalid not-found evidence")
	}
	first, _ := time.Parse(time.RFC3339Nano, r.FirstNotFoundObservedAt)
	last, _ := time.Parse(time.RFC3339Nano, r.LastNotFoundObservedAt)
	if first.Before(acceptedAt) || last.Before(first) || r.NotFoundConfirmations == 1 && (r.FirstNotFoundRequestID != r.LastNotFoundRequestID || r.FirstNotFoundObservedAt != r.LastNotFoundObservedAt) {
		return errors.New("purge receipt has a non-monotonic not-found history")
	}
	return nil
}

func safePurgeEvidenceText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n\t")
}

func optionalPurgeEvidenceText(value string, maximum int) bool {
	return value == "" || safePurgeEvidenceText(value, maximum)
}

func clonePurgeEvidence(evidence PurgeEvidence) PurgeEvidence {
	copyEvidence := evidence
	copyEvidence.Attempts = append([]PurgeAttempt(nil), evidence.Attempts...)
	for index := range copyEvidence.Attempts {
		copyEvidence.Attempts[index].Batches = append([]PurgeReceipt(nil), evidence.Attempts[index].Batches...)
	}
	return copyEvidence
}

func DecodePurgeEvidence(data []byte) (PurgeEvidence, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var evidence PurgeEvidence
	if err := decoder.Decode(&evidence); err != nil {
		return PurgeEvidence{}, fmt.Errorf("decode purge evidence: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return PurgeEvidence{}, err
	}
	canonical, err := evidence.Canonical()
	if err != nil {
		return PurgeEvidence{}, err
	}
	if !bytes.Equal(data, canonical) {
		return PurgeEvidence{}, errors.New("purge evidence is not canonical JSON")
	}
	return evidence, nil
}

// ReadPurgeEvidenceFile performs the same bounded, no-symlink, private-mode
// identity check used by recovery before returning the exact canonical bytes.
func ReadPurgeEvidenceFile(path string) ([]byte, error) {
	return readPurgeEvidenceFile(path)
}

// LoadPurgeEvidenceFile securely reads and strictly decodes one sidecar.
func LoadPurgeEvidenceFile(path string) (PurgeEvidence, []byte, error) {
	body, err := readPurgeEvidenceFile(path)
	if err != nil {
		return PurgeEvidence{}, nil, err
	}
	evidence, err := DecodePurgeEvidence(body)
	if err != nil {
		return PurgeEvidence{}, nil, err
	}
	return evidence, body, nil
}

func readPurgeEvidenceFile(path string) ([]byte, error) {
	directoryPath := filepath.Dir(path)
	root, err := openPurgeEvidenceRoot(directoryPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > purgeEvidenceMaxBytes {
		return nil, errors.New("purge evidence must be a private bounded regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.Join(err, file.Close(), errors.New("purge evidence changed while opening"))
	}
	body, readErr := io.ReadAll(io.LimitReader(file, purgeEvidenceMaxBytes+1))
	readBack, statErr := file.Stat()
	closedErr := file.Close()
	if readErr != nil || statErr != nil || closedErr != nil {
		return nil, errors.Join(readErr, statErr, closedErr)
	}
	if !os.SameFile(info, readBack) || readBack.Size() != info.Size() || !readBack.ModTime().Equal(info.ModTime()) ||
		readBack.Mode()&os.ModeSymlink != 0 || !readBack.Mode().IsRegular() || readBack.Mode().Perm()&0o077 != 0 ||
		len(body) > purgeEvidenceMaxBytes || int64(len(body)) != info.Size() {
		return nil, errors.New("purge evidence exceeded its limit or changed while reading")
	}
	return body, nil
}

func openPurgeEvidenceRoot(directoryPath string) (*os.Root, error) {
	directoryInfo, err := os.Lstat(directoryPath)
	if err != nil {
		return nil, err
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() || directoryInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("purge evidence parent must be a private non-symlink directory")
	}
	root, err := os.OpenRoot(directoryPath)
	if err != nil {
		return nil, err
	}
	openedDirectory, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	openedInfo, statErr := openedDirectory.Stat()
	closeErr := openedDirectory.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(directoryInfo, openedInfo) {
		root.Close()
		return nil, errors.Join(statErr, closeErr, errors.New("purge evidence parent changed while opening"))
	}
	return root, nil
}

func (s purgeEvidenceStore) writeBound(path string, evidence PurgeEvidence) error {
	expected, err := s.path(evidence.Target, evidence.TransactionID)
	if err != nil {
		return err
	}
	if filepath.Clean(path) != filepath.Clean(expected) {
		return errors.New("purge evidence path differs from its binding")
	}
	return s.write(path, evidence)
}

func (s purgeEvidenceStore) write(path string, evidence PurgeEvidence) error {
	if err := s.ensureDirectory(); err != nil {
		return err
	}
	body, err := evidence.Canonical()
	if err != nil {
		return err
	}
	if len(body) > purgeEvidenceMaxBytes {
		return errors.New("purge evidence exceeds its safety limit")
	}
	root, err := openPurgeEvidenceRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(path)
	if info, statErr := root.Lstat(name); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("existing purge evidence is not a private regular file")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	temporary, temporaryName, err := createRootTemp(root, ".purge-evidence-")
	if err != nil {
		return err
	}
	defer root.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := root.Rename(temporaryName, name); err != nil {
		return err
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	return errors.Join(syncErr, directory.Close())
}
