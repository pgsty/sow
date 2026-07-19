package publish

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type cloudflareEvidenceRemote struct {
	*fakeRemote
	receiptCalls       int
	replaceSidecarPath string
	replacementTarget  string
}

func (r *cloudflareEvidenceRemote) CloudflarePurgeEvidenceZoneID() string { return "zone-evidence" }

func (r *cloudflareEvidenceRemote) CloudflarePurgeBatchEvidence(_ context.Context, urls []string) (PurgeReceipt, error) {
	r.receiptCalls++
	if err := r.fakeRemote.purge(urls); err != nil {
		return PurgeReceipt{}, err
	}
	if r.replaceSidecarPath != "" {
		if err := os.Remove(r.replaceSidecarPath); err != nil {
			return PurgeReceipt{}, err
		}
		if err := os.Symlink(r.replacementTarget, r.replaceSidecarPath); err != nil {
			return PurgeReceipt{}, err
		}
	}
	digest, err := PurgeURLsDigest(urls)
	if err != nil {
		return PurgeReceipt{}, err
	}
	stamp := stableTime().Add(time.Duration(r.receiptCalls) * time.Second).Format(time.RFC3339Nano)
	requestID := fmt.Sprintf("cf-ray-%d", r.receiptCalls)
	return PurgeReceipt{
		URLCount: len(urls), URLsSHA256: digest,
		Vendor: PurgeVendorCloudflare, ZoneID: r.CloudflarePurgeEvidenceZoneID(), Status: PurgeReceiptCompleted,
		AcceptedRequestID: requestID, AcceptedObservedAt: stamp,
		CompletedRequestID: requestID, CompletedObservedAt: stamp,
		VendorResultID: "zone-evidence",
	}, nil
}

type edgeEvidenceRemote struct {
	*fakeRemote
	acceptCalls   int
	completeCalls int
	failComplete  bool
	accepted      PurgeReceipt
}

type edgeMissingEvidenceRemote struct {
	*fakeRemote
	acceptCalls   int
	completeCalls int
}

func (r *edgeMissingEvidenceRemote) EdgeOnePurgeEvidenceZoneID() string { return "zone-evidence" }

func (r *edgeMissingEvidenceRemote) EdgeOneAcceptPurgeBatch(_ context.Context, urls []string) (PurgeReceipt, error) {
	r.acceptCalls++
	if err := r.fakeRemote.purge(urls); err != nil {
		return PurgeReceipt{}, err
	}
	digest, err := PurgeURLsDigest(urls)
	if err != nil {
		return PurgeReceipt{}, err
	}
	stamp := stableTime().Add(time.Duration(r.acceptCalls) * time.Minute).Format(time.RFC3339Nano)
	return PurgeReceipt{
		URLCount: len(urls), URLsSHA256: digest,
		Vendor: PurgeVendorEdgeOne, ZoneID: r.EdgeOnePurgeEvidenceZoneID(), Status: PurgeReceiptAccepted,
		JobID: fmt.Sprintf("job-missing-%d", r.acceptCalls), AcceptedRequestID: fmt.Sprintf("create-missing-%d", r.acceptCalls),
		AcceptedObservedAt: stamp,
	}, nil
}

func (r *edgeMissingEvidenceRemote) EdgeOneCompletePurgeBatch(_ context.Context, accepted PurgeReceipt) (PurgeReceipt, error) {
	r.completeCalls++
	if accepted.JobID == "job-missing-1" {
		updated := accepted
		updated.NotFoundConfirmations++
		requestID := fmt.Sprintf("describe-missing-%d", updated.NotFoundConfirmations)
		observed := stableTime().Add(time.Duration(updated.NotFoundConfirmations+2) * time.Minute).Format(time.RFC3339Nano)
		if updated.NotFoundConfirmations == 1 {
			updated.FirstNotFoundRequestID, updated.FirstNotFoundObservedAt = requestID, observed
		}
		updated.LastNotFoundRequestID, updated.LastNotFoundObservedAt = requestID, observed
		if updated.NotFoundConfirmations >= 2 {
			updated.Status = PurgeReceiptIndeterminate
			updated.IndeterminateRequestID, updated.IndeterminateObservedAt = requestID, observed
		}
		return updated, errors.New("accepted EdgeOne job is absent from exact status queries")
	}
	completed := accepted
	completed.Status = PurgeReceiptCompleted
	completed.CompletedRequestID = "describe-replacement-complete"
	completed.CompletedObservedAt = stableTime().Add(10 * time.Minute).Format(time.RFC3339Nano)
	return completed, nil
}

func (r *edgeEvidenceRemote) EdgeOnePurgeEvidenceZoneID() string { return "zone-evidence" }

func (r *edgeEvidenceRemote) EdgeOneAcceptPurgeBatch(_ context.Context, urls []string) (PurgeReceipt, error) {
	r.acceptCalls++
	if err := r.fakeRemote.purge(urls); err != nil {
		return PurgeReceipt{}, err
	}
	digest, err := PurgeURLsDigest(urls)
	if err != nil {
		return PurgeReceipt{}, err
	}
	r.accepted = PurgeReceipt{
		URLCount: len(urls), URLsSHA256: digest,
		Vendor: PurgeVendorEdgeOne, ZoneID: r.EdgeOnePurgeEvidenceZoneID(), Status: PurgeReceiptAccepted,
		JobID: "job-evidence-1", AcceptedRequestID: "create-request-1",
		AcceptedObservedAt: stableTime().Format(time.RFC3339Nano),
	}
	return r.accepted, nil
}

func (r *edgeEvidenceRemote) EdgeOneCompletePurgeBatch(_ context.Context, accepted PurgeReceipt) (PurgeReceipt, error) {
	r.completeCalls++
	if accepted != r.accepted {
		return accepted, errors.New("completion changed the accepted job")
	}
	if r.failComplete {
		r.failComplete = false
		return accepted, errors.New("injected DescribePurgeTasks response loss")
	}
	completed := accepted
	completed.Status = PurgeReceiptCompleted
	completed.CompletedRequestID = "describe-request-1"
	completed.CompletedObservedAt = stableTime().Add(time.Second).Format(time.RFC3339Nano)
	return completed, nil
}

func TestRequiredPurgeEvidenceFailsBeforeRemoteMutation(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := newFakeRemote()
	publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, filepath.Join(t.TempDir(), "journal"), Hooks{}).
		WithRequiredPurgeEvidence()
	_, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, "required-evidence"))
	if !errors.Is(err, ErrCapability) {
		t.Fatalf("provider without evidence capability err=%v", err)
	}
	if len(remote.objects) != 0 || len(remote.purgeCalls) != 0 {
		t.Fatalf("capability failure mutated remote objects=%d purges=%d", len(remote.objects), len(remote.purgeCalls))
	}
}

func TestEdgeOneAcceptedPurgeEvidenceResumesSameJob(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := &edgeEvidenceRemote{fakeRemote: newFakeRemote(), failComplete: true}
	journalDir := filepath.Join(t.TempDir(), "journal")
	request := requestFixture(TargetTencent, plan, "edge-evidence-resume")
	first := NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{}).WithRequiredPurgeEvidence()
	firstResult, err := first.Run(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "DescribePurgeTasks response loss") {
		t.Fatalf("first evidence run did not stop after accepted receipt: %v", err)
	}
	if remote.acceptCalls != 1 || remote.completeCalls != 1 {
		t.Fatalf("first evidence calls accept=%d complete=%d", remote.acceptCalls, remote.completeCalls)
	}
	evidence, _, err := LoadPurgeEvidenceFile(firstResult.PurgeEvidencePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Attempts) != 1 || len(evidence.Attempts[0].Batches) != 1 || evidence.Attempts[0].Batches[0].Status != PurgeReceiptAccepted {
		t.Fatalf("accepted job was not durably retained: %#v", evidence)
	}

	second := NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{}).WithRequiredPurgeEvidence()
	result, err := second.Run(context.Background(), request)
	if err != nil || !result.RemoteRefReady {
		t.Fatalf("resume result=%#v err=%v", result, err)
	}
	if remote.acceptCalls != 1 || remote.completeCalls != 2 {
		t.Fatalf("recovery recreated accepted job accept=%d complete=%d", remote.acceptCalls, remote.completeCalls)
	}
	evidence, body, err := LoadPurgeEvidenceFile(result.PurgeEvidencePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Attempts) != 1 || evidence.ValidateFullClosure(1, request.Plan.PurgeURLs) != nil || digestBytes(body) != result.PurgeEvidenceSHA256 {
		t.Fatalf("completed evidence closure/result mismatch: %#v", evidence)
	}
}

func TestEdgeOneRepeatedMissingAcceptedJobStartsNewExactAttempt(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := &edgeMissingEvidenceRemote{fakeRemote: newFakeRemote()}
	journalDir := filepath.Join(t.TempDir(), "journal")
	request := requestFixture(TargetTencent, plan, "edge-evidence-missing-job")

	first, err := NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{}).
		WithRequiredPurgeEvidence().Run(context.Background(), request)
	if err == nil || first.PurgeEvidencePath == "" {
		t.Fatalf("first missing-job confirmation result=%#v err=%v", first, err)
	}
	evidence, _, loadErr := LoadPurgeEvidenceFile(first.PurgeEvidencePath)
	if loadErr != nil || len(evidence.Attempts) != 1 || len(evidence.Attempts[0].Batches) != 1 ||
		evidence.Attempts[0].Batches[0].Status != PurgeReceiptAccepted || evidence.Attempts[0].Batches[0].NotFoundConfirmations != 1 {
		t.Fatalf("first missing-job confirmation was not durable: %#v err=%v", evidence, loadErr)
	}

	second, err := NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{}).
		WithRequiredPurgeEvidence().Run(context.Background(), request)
	if err == nil || second.PurgeEvidencePath == "" {
		t.Fatalf("second missing-job confirmation result=%#v err=%v", second, err)
	}
	evidence, _, loadErr = LoadPurgeEvidenceFile(second.PurgeEvidencePath)
	if loadErr != nil || evidence.Attempts[0].Batches[0].Status != PurgeReceiptIndeterminate || evidence.Attempts[0].Batches[0].NotFoundConfirmations != 2 {
		t.Fatalf("repeated missing job was not made audibly indeterminate: %#v err=%v", evidence, loadErr)
	}

	third, err := NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{}).
		WithRequiredPurgeEvidence().Run(context.Background(), request)
	if err != nil || !third.RemoteRefReady {
		t.Fatalf("replacement exact attempt result=%#v err=%v", third, err)
	}
	evidence, _, loadErr = LoadPurgeEvidenceFile(third.PurgeEvidencePath)
	if loadErr != nil || len(evidence.Attempts) != 2 || evidence.ValidateFullClosure(2, request.Plan.PurgeURLs) != nil ||
		remote.acceptCalls != 2 || remote.completeCalls != 3 {
		t.Fatalf("replacement exact attempt closure=%#v accepts=%d completes=%d err=%v", evidence, remote.acceptCalls, remote.completeCalls, loadErr)
	}
}

func TestPurgeEvidenceWriteFailureCannotAdvanceJournal(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	journalDir := filepath.Join(t.TempDir(), "journal")
	transactionID := "evidence-write-failure"
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("do-not-touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	remote := &cloudflareEvidenceRemote{fakeRemote: newFakeRemote()}
	remote.replaceSidecarPath = filepath.Join(journalDir, string(TargetCloudflare)+"-"+transactionID+".purge.json")
	remote.replacementTarget = victim
	publisher := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{}).WithRequiredPurgeEvidence()
	_, err := publisher.Run(context.Background(), requestFixture(TargetCloudflare, plan, transactionID))
	if err == nil || !strings.Contains(err.Error(), "existing purge evidence is not a private regular file") {
		t.Fatalf("unsafe evidence replacement err=%v", err)
	}
	journalBody, err := readJournalFile(filepath.Join(journalDir, string(TargetCloudflare)+"-"+transactionID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := decodeJournal(journalBody)
	if err != nil || journal.Phase != PhasePointerFlipped {
		t.Fatalf("journal advanced without durable purge evidence: %#v err=%v", journal, err)
	}
	checkpoint, err := DecodeCheckpoint(remote.get(CheckpointKey).Body)
	if err != nil || checkpoint.Phase != PhaseLocked {
		t.Fatalf("checkpoint advanced without durable purge evidence: %#v err=%v", checkpoint, err)
	}
	victimBody, err := os.ReadFile(victim)
	if err != nil || string(victimBody) != "do-not-touch" {
		t.Fatalf("replacement victim changed body=%q err=%v", victimBody, err)
	}
}

func TestCommittedReplayAppendsFreshPurgeEvidenceAttempt(t *testing.T) {
	t.Parallel()
	root, plan := sourcePlan(t)
	remote := &cloudflareEvidenceRemote{fakeRemote: newFakeRemote()}
	journalDir := filepath.Join(t.TempDir(), "journal")
	request := requestFixture(TargetCloudflare, plan, "evidence-committed-replay")
	first, err := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{}).
		WithRequiredPurgeEvidence().Run(context.Background(), request)
	if err != nil || !first.RemoteRefReady {
		t.Fatalf("first result=%#v err=%v", first, err)
	}
	second, err := NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{}).
		WithRequiredPurgeEvidence().Run(context.Background(), request)
	if err != nil || !second.RemoteRefReady {
		t.Fatalf("replay result=%#v err=%v", second, err)
	}
	evidence, _, err := LoadPurgeEvidenceFile(second.PurgeEvidencePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Attempts) != 2 || evidence.ValidateFullClosure(2, request.Plan.PurgeURLs) != nil || remote.receiptCalls != 2 {
		t.Fatalf("committed replay did not append fresh proof: attempts=%d receipts=%d", len(evidence.Attempts), remote.receiptCalls)
	}
}
