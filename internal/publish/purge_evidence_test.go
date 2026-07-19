package publish

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func purgeEvidenceTestBinding(urls []string) PurgeEvidenceBinding {
	return PurgeEvidenceBinding{
		Target: TargetCloudflare, TransactionID: "purge-evidence-test", Generation: 7,
		GenerationSHA256: strings.Repeat("1", 64), PlanSHA256: strings.Repeat("2", 64),
		CheckpointSHA256: strings.Repeat("3", 64), URLs: urls,
	}
}

func purgeEvidenceTestURLs(count int) []string {
	urls := make([]string, count)
	for index := range urls {
		urls[index] = fmt.Sprintf("https://cdn.test/pointer-%03d", count-index-1)
	}
	return urls
}

func purgeEvidenceTestCloudflareReceipt(t *testing.T, batchIndex int, urls []string, stamp string) PurgeReceipt {
	t.Helper()
	digest, err := PurgeURLsDigest(urls)
	if err != nil {
		t.Fatal(err)
	}
	return PurgeReceipt{
		BatchIndex: batchIndex, URLCount: len(urls), URLsSHA256: digest,
		Vendor: PurgeVendorCloudflare, ZoneID: "zone-cf", Status: PurgeReceiptCompleted,
		AcceptedRequestID: fmt.Sprintf("ray-%d-SJC", batchIndex), AcceptedObservedAt: stamp,
		CompletedRequestID: fmt.Sprintf("ray-%d-SJC", batchIndex), CompletedObservedAt: stamp,
		VendorResultID: "zone-cf",
	}
}

func TestPurgeEvidenceURLDigestIsSortedUniqueCanonicalJSON(t *testing.T) {
	t.Parallel()
	left, err := PurgeURLsDigest([]string{"https://cdn.test/b", "https://cdn.test/a"})
	if err != nil {
		t.Fatal(err)
	}
	right, err := PurgeURLsDigest([]string{"https://cdn.test/a", "https://cdn.test/b"})
	if err != nil {
		t.Fatal(err)
	}
	if left != right || len(left) != 64 {
		t.Fatalf("canonical URL digest mismatch left=%s right=%s", left, right)
	}
	if _, err := PurgeURLsDigest([]string{"https://cdn.test/a", "https://cdn.test/a"}); err == nil {
		t.Fatal("duplicate purge URL was silently collapsed")
	}
	if _, err := PurgeURLsDigest([]string{"https://cdn.test/a\nsecret"}); err == nil {
		t.Fatal("unsafe purge URL was accepted")
	}
}

func TestPurgeEvidenceStoreLifecycleAndFullClosure(t *testing.T) {
	t.Parallel()
	stamp := time.Date(2026, 7, 14, 4, 5, 6, 7, time.UTC)
	store := purgeEvidenceStore{dir: filepath.Join(t.TempDir(), "journal"), now: func() time.Time { return stamp }}
	urls := purgeEvidenceTestURLs(205)
	binding := purgeEvidenceTestBinding(urls)
	evidence, created, path, err := store.loadOrCreate(binding)
	if err != nil || !created {
		t.Fatalf("create purge evidence created=%t err=%v", created, err)
	}
	if filepath.Base(path) != "cf-purge-evidence-test.purge.json" {
		t.Fatalf("unexpected sidecar path %s", path)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("sidecar mode=%v err=%v", info, err)
	}
	attemptID, err := store.beginAttempt(path, evidence, PurgeAttemptFull, urls)
	if err != nil || attemptID != 1 {
		t.Fatalf("begin full attempt id=%d err=%v", attemptID, err)
	}
	canonical := append([]string(nil), urls...)
	sort.Strings(canonical)
	for batchIndex, start := 0, 0; start < len(canonical); batchIndex, start = batchIndex+1, start+purgeEvidenceBatchMaxURLs {
		end := min(start+purgeEvidenceBatchMaxURLs, len(canonical))
		batch := canonical[start:end]
		receipt := purgeEvidenceTestCloudflareReceipt(t, batchIndex, batch, stamp.Format(time.RFC3339Nano))
		if err := store.persistBatchCompleted(path, evidence, attemptID, batch, receipt); err != nil {
			t.Fatalf("persist batch %d: %v", batchIndex, err)
		}
	}
	if err := evidence.ValidateFullClosure(attemptID, urls); err != nil {
		t.Fatalf("validate complete closure: %v", err)
	}
	reloaded, created, reloadedPath, err := store.loadOrCreate(binding)
	if err != nil || created || reloadedPath != path {
		t.Fatalf("reload created=%t path=%s err=%v", created, reloadedPath, err)
	}
	if err := validateFullClosure(reloaded, attemptID, urls); err != nil {
		t.Fatalf("validate reloaded closure: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	canonicalBody, err := reloaded.Canonical()
	if err != nil || !bytes.Equal(body, canonicalBody) {
		t.Fatalf("sidecar is not exact canonical JSON err=%v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("atomic writer left temporary files: entries=%v err=%v", entries, err)
	}
}

func TestPurgeEvidenceEdgeOneAcceptanceCompletionIsMonotonic(t *testing.T) {
	t.Parallel()
	acceptedAt := time.Date(2026, 7, 14, 5, 0, 0, 0, time.UTC)
	completedAt := acceptedAt.Add(2 * time.Second)
	clock := acceptedAt
	store := purgeEvidenceStore{dir: filepath.Join(t.TempDir(), "journal"), now: func() time.Time { return clock }}
	urls := []string{"https://cdn.test/pointer"}
	binding := purgeEvidenceTestBinding(urls)
	binding.Target = TargetTencent
	evidence, _, path, err := store.loadOrCreate(binding)
	if err != nil {
		t.Fatal(err)
	}
	attemptID, err := store.beginAttempt(path, evidence, PurgeAttemptFull, urls)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := PurgeURLsDigest(urls)
	accepted := PurgeReceipt{
		BatchIndex: 0, URLCount: 1, URLsSHA256: digest,
		Vendor: PurgeVendorEdgeOne, ZoneID: "zone-eo", Status: PurgeReceiptAccepted,
		JobID: "job-1", AcceptedRequestID: "create-request-1", AcceptedObservedAt: acceptedAt.Format(time.RFC3339Nano),
	}
	if err := store.persistBatchAccepted(path, evidence, attemptID, urls, accepted); err != nil {
		t.Fatal(err)
	}
	if err := evidence.ValidateFullClosure(attemptID, urls); err == nil {
		t.Fatal("accepted but incomplete job passed full closure")
	}
	clock = completedAt
	completed := accepted
	completed.Status = PurgeReceiptCompleted
	completed.CompletedRequestID = "describe-request-1"
	completed.CompletedObservedAt = completedAt.Format(time.RFC3339Nano)
	completed.ProviderCreatedAt = "2026-07-14T13:00:00+08:00"
	completed.ProviderUpdatedAt = "2026-07-14T13:00:02+08:00"
	if err := store.persistBatchCompleted(path, evidence, attemptID, urls, completed); err != nil {
		t.Fatal(err)
	}
	if err := evidence.ValidateFullClosure(attemptID, urls); err != nil {
		t.Fatal(err)
	}
	failed := completed
	failed.Status = PurgeReceiptFailed
	failed.CompletedRequestID = ""
	failed.CompletedObservedAt = ""
	failed.FailedRequestID = "describe-request-2"
	failed.FailedObservedAt = completedAt.Add(time.Second).Format(time.RFC3339Nano)
	if err := store.persistBatchFailed(path, evidence, attemptID, urls, failed); err == nil {
		t.Fatal("completed receipt transitioned backward to failed")
	}
}

func TestPurgeEvidenceEdgeOneNotFoundHistoryCannotRegressOrReuseAResponse(t *testing.T) {
	t.Parallel()
	acceptedAt := time.Date(2026, 7, 14, 5, 0, 0, 0, time.UTC)
	existing := PurgeReceipt{
		BatchIndex: 0, URLCount: 1, URLsSHA256: strings.Repeat("1", 64),
		Vendor: PurgeVendorEdgeOne, ZoneID: "zone-eo", Status: PurgeReceiptAccepted,
		JobID: "job-1", AcceptedRequestID: "create-request-1", AcceptedObservedAt: acceptedAt.Format(time.RFC3339Nano),
		NotFoundConfirmations: 1, FirstNotFoundRequestID: "missing-1", LastNotFoundRequestID: "missing-1",
		FirstNotFoundObservedAt: acceptedAt.Add(2 * time.Minute).Format(time.RFC3339Nano),
		LastNotFoundObservedAt:  acceptedAt.Add(2 * time.Minute).Format(time.RFC3339Nano),
	}
	valid := existing
	valid.NotFoundConfirmations = 2
	valid.LastNotFoundRequestID = "missing-2"
	valid.LastNotFoundObservedAt = acceptedAt.Add(4 * time.Minute).Format(time.RFC3339Nano)
	if merged, err := mergePurgeReceipt(existing, valid); err != nil || merged != valid {
		t.Fatalf("monotonic independent not-found response rejected merged=%#v err=%v", merged, err)
	}
	for name, mutate := range map[string]func(*PurgeReceipt){
		"regressed-time": func(receipt *PurgeReceipt) {
			receipt.LastNotFoundObservedAt = acceptedAt.Add(time.Minute).Format(time.RFC3339Nano)
		},
		"reused-request": func(receipt *PurgeReceipt) {
			receipt.LastNotFoundRequestID = existing.LastNotFoundRequestID
		},
	} {
		t.Run(name, func(t *testing.T) {
			incoming := valid
			mutate(&incoming)
			if _, err := mergePurgeReceipt(existing, incoming); err == nil {
				t.Fatal("non-independent or regressed not-found history was accepted")
			}
		})
	}
}

func TestPurgeEvidenceBindingDriftFailsClosed(t *testing.T) {
	t.Parallel()
	store := purgeEvidenceStore{dir: filepath.Join(t.TempDir(), "journal")}
	binding := purgeEvidenceTestBinding([]string{"https://cdn.test/a"})
	if _, _, _, err := store.loadOrCreate(binding); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*PurgeEvidenceBinding){
		func(value *PurgeEvidenceBinding) { value.Generation++ },
		func(value *PurgeEvidenceBinding) { value.GenerationSHA256 = strings.Repeat("4", 64) },
		func(value *PurgeEvidenceBinding) { value.PlanSHA256 = strings.Repeat("5", 64) },
		func(value *PurgeEvidenceBinding) { value.CheckpointSHA256 = strings.Repeat("6", 64) },
		func(value *PurgeEvidenceBinding) { value.URLs = []string{"https://cdn.test/b"} },
	} {
		changed := binding
		mutate(&changed)
		if _, _, _, err := store.loadOrCreate(changed); !errors.Is(err, ErrJournalConflict) {
			t.Fatalf("binding drift error=%v, want ErrJournalConflict", err)
		}
	}
}

func TestPurgeEvidenceStrictDecodeRejectsUnknownTamperAndTrailingJSON(t *testing.T) {
	t.Parallel()
	store := purgeEvidenceStore{dir: filepath.Join(t.TempDir(), "journal")}
	binding := purgeEvidenceTestBinding([]string{"https://cdn.test/a"})
	_, _, path, err := store.loadOrCreate(binding)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(body, []byte(`{"schema":`), []byte(`{"unknown":true,"schema":`), 1)
	if _, err := DecodePurgeEvidence(unknown); err == nil {
		t.Fatal("unknown purge evidence field was accepted")
	}
	trailing := append(append([]byte(nil), body...), []byte("\n{}")...)
	if _, err := DecodePurgeEvidence(trailing); err == nil {
		t.Fatal("trailing purge evidence JSON was accepted")
	}
	for name, invalid := range map[string][]byte{"unknown": unknown, "trailing": trailing} {
		if err := os.WriteFile(path, invalid, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := store.loadOrCreate(binding); !errors.Is(err, ErrJournalConflict) {
			t.Fatalf("%s existing sidecar error=%v, want ErrJournalConflict", name, err)
		}
	}
	tampered := bytes.Replace(body, []byte(strings.Repeat("2", 64)), []byte(strings.Repeat("f", 64)), 1)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.loadOrCreate(binding); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("tampered binding error=%v, want ErrJournalConflict", err)
	}
}

func TestPurgeEvidenceRejectsUnsafeFilesAndParents(t *testing.T) {
	t.Parallel()
	binding := purgeEvidenceTestBinding([]string{"https://cdn.test/a"})
	t.Run("world-readable", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "journal")
		store := purgeEvidenceStore{dir: directory}
		_, _, path, err := store.loadOrCreate(binding)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := store.loadOrCreate(binding); !errors.Is(err, ErrJournalConflict) {
			t.Fatalf("world-readable purge evidence error=%v, want ErrJournalConflict", err)
		}
	})
	t.Run("symlink-file", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "journal")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		store := purgeEvidenceStore{dir: directory}
		path, err := store.path(binding.Target, binding.TransactionID)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target.json")
		if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := store.loadOrCreate(binding); !errors.Is(err, ErrJournalConflict) {
			t.Fatalf("symlink purge evidence error=%v, want ErrJournalConflict", err)
		}
	})
	t.Run("symlink-parent", func(t *testing.T) {
		root := t.TempDir()
		realDirectory := filepath.Join(root, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedDirectory := filepath.Join(root, "journal")
		if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
			t.Fatal(err)
		}
		store := purgeEvidenceStore{dir: linkedDirectory}
		if _, _, _, err := store.loadOrCreate(binding); !errors.Is(err, ErrJournalConflict) {
			t.Fatalf("symlink purge evidence parent error=%v, want ErrJournalConflict", err)
		}
	})
}

func TestPurgeEvidenceFullClosureRejectsMissingFailedAndWrongBatch(t *testing.T) {
	t.Parallel()
	stamp := time.Date(2026, 7, 14, 6, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	urls := purgeEvidenceTestURLs(101)
	canonical := append([]string(nil), urls...)
	sort.Strings(canonical)
	store := purgeEvidenceStore{dir: filepath.Join(t.TempDir(), "journal")}
	evidence, _, path, err := store.loadOrCreate(purgeEvidenceTestBinding(urls))
	if err != nil {
		t.Fatal(err)
	}
	attemptID, err := store.beginAttempt(path, evidence, PurgeAttemptFull, urls)
	if err != nil {
		t.Fatal(err)
	}
	first := purgeEvidenceTestCloudflareReceipt(t, 0, canonical[:100], stamp)
	if err := store.persistBatchCompleted(path, evidence, attemptID, canonical[:100], first); err != nil {
		t.Fatal(err)
	}
	if err := evidence.ValidateFullClosure(attemptID, urls); err == nil {
		t.Fatal("missing final batch passed closure")
	}
	wrongURLs := []string{"https://cdn.test/not-the-bound-final-url"}
	wrong := purgeEvidenceTestCloudflareReceipt(t, 1, wrongURLs, stamp)
	if err := store.persistBatchCompleted(path, evidence, attemptID, wrongURLs, wrong); err != nil {
		t.Fatal(err)
	}
	if err := evidence.ValidateFullClosure(attemptID, urls); err == nil {
		t.Fatal("wrong final batch digest passed closure")
	}

	failedStore := purgeEvidenceStore{dir: filepath.Join(t.TempDir(), "journal")}
	failedEvidence, _, failedPath, err := failedStore.loadOrCreate(purgeEvidenceTestBinding([]string{"https://cdn.test/a"}))
	if err != nil {
		t.Fatal(err)
	}
	failedAttempt, err := failedStore.beginAttempt(failedPath, failedEvidence, PurgeAttemptFull, []string{"https://cdn.test/a"})
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := PurgeURLsDigest([]string{"https://cdn.test/a"})
	accepted := PurgeReceipt{BatchIndex: 0, URLCount: 1, URLsSHA256: digest, Vendor: PurgeVendorEdgeOne, ZoneID: "zone", Status: PurgeReceiptAccepted, JobID: "job", AcceptedRequestID: "create", AcceptedObservedAt: stamp}
	if err := failedStore.persistBatchAccepted(failedPath, failedEvidence, failedAttempt, []string{"https://cdn.test/a"}, accepted); err != nil {
		t.Fatal(err)
	}
	failed := accepted
	failed.Status = PurgeReceiptFailed
	failed.FailedRequestID = "describe"
	failed.FailedObservedAt = stamp
	if err := failedStore.persistBatchFailed(failedPath, failedEvidence, failedAttempt, []string{"https://cdn.test/a"}, failed); err != nil {
		t.Fatal(err)
	}
	if err := failedEvidence.ValidateFullClosure(failedAttempt, []string{"https://cdn.test/a"}); err == nil {
		t.Fatal("failed provider job passed full closure")
	}
}

func TestPurgeEvidenceWriteRefusesPathOutsideItsBinding(t *testing.T) {
	t.Parallel()
	store := purgeEvidenceStore{dir: filepath.Join(t.TempDir(), "journal")}
	evidence, _, _, err := store.loadOrCreate(purgeEvidenceTestBinding([]string{"https://cdn.test/a"}))
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(store.dir, "different.purge.json")
	if err := store.writeBound(outside, *evidence); err == nil {
		t.Fatal("purge evidence was written outside its bound sidecar path")
	}
	if _, err := os.Lstat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected outside file: %v", err)
	}
}
