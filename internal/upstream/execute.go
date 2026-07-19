package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/syncer"
	"github.com/pgsty/sow/internal/yumrepo"
)

// Executor applies an additive plan with bounded download concurrency. Every
// successful body is verified by syncer.Downloader before its immutable
// provenance receipt is committed. It never removes or enumerates local
// artifacts, so disappearance upstream cannot translate into local deletion.
type Executor struct {
	Downloader              syncer.Downloader
	DownloadDir             string
	Provenance              *provenance.Store
	Workers                 int
	Now                     func() time.Time
	RPMPackageKeyring       openpgp.KeyRing
	RPMPackageKeyringSHA256 string
}

type Downloaded struct {
	Candidate  syncer.Candidate
	Path       string
	ReceiptID  string
	NewReceipt bool
}

// ReceiptCommit records provenance added (or idempotently reused) for an
// artifact already present in the caller's inventory.
type ReceiptCommit struct {
	Candidate  syncer.Candidate
	ReceiptID  string
	NewReceipt bool
}

type SyncResult struct {
	Plan       syncer.Plan
	Downloaded []Downloaded
	Present    []ReceiptCommit
}

// ResultSink receives execution results as they complete. Executor serializes
// calls, so sinks can append to a disk journal without their own mutex.
type ResultSink interface {
	PutDownloaded(Downloaded) error
	PutPresent(ReceiptCommit) error
}

// ArtifactOpener lets a production inventory provide already-present package
// bytes for digest and, for RPM, signature inspection without weakening the
// minimal Has contract used by the generic sync planner.
type ArtifactOpener interface {
	OpenArtifact(sha256 string, size int64) (io.ReadSeekCloser, error)
}

type sliceResultSink struct {
	downloaded []Downloaded
	present    []ReceiptCommit
}

func (s *sliceResultSink) PutDownloaded(value Downloaded) error {
	s.downloaded = append(s.downloaded, value)
	return nil
}

func (s *sliceResultSink) PutPresent(value ReceiptCommit) error {
	s.present = append(s.present, value)
	return nil
}

// Run filters and diffs a discovery, then downloads only absent artifacts.
// On a partial failure it returns completed entries alongside the error; .part
// files intentionally remain so an identical replay resumes with HTTP Range.
func (e Executor) Run(ctx context.Context, discovery *Discovery, filter syncer.Filter, inventory syncer.Inventory) (*SyncResult, error) {
	if err := validateMaterializedCandidates(discovery); err != nil {
		return nil, err
	}
	sink := &sliceResultSink{}
	result, err := e.RunStreaming(ctx, discovery, filter, inventory, sink)
	if result == nil {
		return nil, err
	}
	result.Downloaded = sink.downloaded
	result.Present = sink.present
	result.Plan.Download = make([]syncer.Candidate, 0, len(result.Downloaded))
	for _, downloaded := range result.Downloaded {
		result.Plan.Download = append(result.Plan.Download, downloaded.Candidate)
	}
	sort.Slice(result.Plan.Download, func(i, j int) bool {
		left, right := result.Plan.Download[i], result.Plan.Download[j]
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Arch != right.Arch {
			return left.Arch < right.Arch
		}
		if left.Version != right.Version {
			return left.Version < right.Version
		}
		return left.SHA256 < right.SHA256
	})
	return result, err
}

// RunStreaming filters and diffs the disk-backed discovery, then downloads
// missing bodies through a bounded worker queue. Results are emitted to sink
// instead of being retained in repository-sized slices.
func (e Executor) RunStreaming(ctx context.Context, discovery *Discovery, filter syncer.Filter, inventory syncer.Inventory, sink ResultSink) (*SyncResult, error) {
	if ctx == nil {
		return nil, errors.New("upstream: nil context")
	}
	if discovery == nil || (discovery.Format != "deb" && discovery.Format != "rpm") || discovery.store == nil {
		return nil, fmt.Errorf("%w: invalid discovery", ErrInvalidMetadata)
	}
	if e.DownloadDir == "" || e.Provenance == nil || inventory == nil || sink == nil {
		return nil, errors.New("upstream: download directory, provenance store, inventory, and result sink are required")
	}
	if err := discovery.ValidateEvidence(); err != nil {
		return nil, err
	}
	result := &SyncResult{}
	observed := time.Now().UTC()
	if e.Now != nil {
		observed = e.Now().UTC()
	}
	if observed.IsZero() {
		return nil, errors.New("upstream: observation time must be non-zero")
	}
	if discovery.Format == "rpm" && (e.RPMPackageKeyring == nil || len(e.RPMPackageKeyringSHA256) != 64) {
		return nil, fmt.Errorf("%w: RPM package keyring and SHA-256 trust identity are required", ErrEvidence)
	}
	workers := e.Workers
	if workers <= 0 {
		workers = 4
	}
	if workers > 128 {
		return result, fmt.Errorf("%w: worker count %d exceeds 128", ErrInvalidMetadata, workers)
	}
	downloader := e.Downloader
	downloader.Client = secureHTTPClient(downloader.Client)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan syncer.Candidate, workers*2)
	var wg sync.WaitGroup
	var errorOnce sync.Once
	var firstError error
	var sinkMu sync.Mutex
	recordError := func(err error) {
		errorOnce.Do(func() {
			firstError = err
			cancel()
		})
	}
	worker := func() {
		defer wg.Done()
		for candidate := range jobs {
			if ctx.Err() != nil {
				continue
			}
			file, err := verifiedDownload(ctx, candidate, e.DownloadDir, downloader)
			if err == nil {
				var receipt provenance.Receipt
				receipt, err = receiptForDownloadedArtifact(ctx, discovery, candidate, observed, file, e.RPMPackageKeyring, e.RPMPackageKeyringSHA256)
				if err == nil {
					var completed Downloaded
					completed, err = commitReceipt(e.Provenance, candidate, file, receipt)
					if err == nil {
						sinkMu.Lock()
						err = sink.PutDownloaded(completed)
						sinkMu.Unlock()
					}
				}
			}
			if err != nil {
				recordError(fmt.Errorf("upstream: sync %s@%s: %w", candidate.Name, candidate.Arch, err))
			}
		}
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}
	present := func(candidate syncer.Candidate) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if committed, reusable, err := reusablePresentReceipt(e.Provenance, candidate, e.RPMPackageKeyringSHA256); err != nil {
			return err
		} else if reusable {
			sinkMu.Lock()
			err = sink.PutPresent(committed)
			sinkMu.Unlock()
			return err
		}
		opener, ok := inventory.(ArtifactOpener)
		if !ok {
			return fmt.Errorf("%w: present artifact inventory cannot open %s for digest verification", ErrEvidence, candidate.SHA256)
		}
		reader, err := opener.OpenArtifact(candidate.SHA256, candidate.Size)
		if err != nil {
			return fmt.Errorf("%w: open present artifact %s: %v", ErrEvidence, candidate.SHA256, err)
		}
		receipt, err := receiptForArtifact(ctx, discovery, candidate, observed, reader, e.RPMPackageKeyring, e.RPMPackageKeyringSHA256)
		err = errors.Join(err, reader.Close())
		if err != nil {
			return err
		}
		committed, err := commitReceipt(e.Provenance, candidate, "", receipt)
		if err != nil {
			return err
		}
		sinkMu.Lock()
		err = sink.PutPresent(ReceiptCommit{Candidate: candidate, ReceiptID: committed.ReceiptID, NewReceipt: committed.NewReceipt})
		sinkMu.Unlock()
		return err
	}
	download := func(candidate syncer.Candidate) error {
		select {
		case jobs <- candidate:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	stream := func(yield func(syncer.Candidate) error) error {
		return discovery.ForEachCandidateContext(ctx, yield)
	}
	plan, planErr := syncer.BuildPlanStream(stream, filter, inventory, present, download)
	result.Plan = plan
	if planErr != nil {
		recordError(planErr)
	}
	close(jobs)
	wg.Wait()
	if firstError != nil {
		return result, firstError
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}

// reusablePresentReceipt is the cheap incremental path required by FR-06.
// An unchanged artifact with an existing first-valid receipt needs no whole-
// body audit merely because upstream metadata rotated. If the artifact is not
// yet in the selected view, the CLI's change-set staging path independently
// calls repository.Store.Verify before linking it. Explicit fsck remains the
// only full-repository audit path.
//
// RPM receipts are reusable only when they carry current v3 cryptographic
// evidence under the exact current package-trust bundle. Keyring rotation and
// legacy/v2 receipts deliberately fall through to same-FD digest+signature
// verification before the immutable first receipt is retained.
func reusablePresentReceipt(store *provenance.Store, candidate syncer.Candidate, packageKeyringSHA256 string) (ReceiptCommit, bool, error) {
	if store == nil {
		return ReceiptCommit{}, false, errors.New("upstream: provenance store is required")
	}
	receipt, err := store.Get(candidate.Format, candidate.SHA256)
	if errors.Is(err, os.ErrNotExist) {
		return ReceiptCommit{}, false, nil
	}
	if err != nil {
		return ReceiptCommit{}, false, err
	}
	if receipt.Format != candidate.Format || receipt.ArtifactSHA256 != candidate.SHA256 || receipt.ArtifactSize != candidate.Size {
		return ReceiptCommit{}, false, fmt.Errorf("%w: existing provenance does not match present artifact %s", ErrEvidence, candidate.SHA256)
	}
	if candidate.Format == "rpm" && (receipt.Schema != provenance.Schema || receipt.RPM == nil ||
		receipt.RPM.SignatureVerification != "verified" || receipt.RPM.PackageKeyringSHA256 != packageKeyringSHA256 ||
		len(receipt.RPM.EmbeddedSignatures) == 0) {
		return ReceiptCommit{}, false, nil
	}
	id, err := receipt.ID()
	if err != nil {
		return ReceiptCommit{}, false, err
	}
	return ReceiptCommit{Candidate: candidate, ReceiptID: id}, true, nil
}

func receiptForDownloadedArtifact(ctx context.Context, discovery *Discovery, candidate syncer.Candidate, observed time.Time, filename string, keyring openpgp.KeyRing, packageKeyringSHA256 string) (provenance.Receipt, error) {
	before, err := os.Lstat(filename)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() != candidate.Size {
		return provenance.Receipt{}, fmt.Errorf("%w: downloaded artifact is not a stable regular file", ErrEvidence)
	}
	file, err := os.Open(filename)
	if err != nil {
		return provenance.Receipt{}, fmt.Errorf("%w: open downloaded artifact: %v", ErrEvidence, err)
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return provenance.Receipt{}, fmt.Errorf("%w: downloaded artifact changed while opening", ErrEvidence)
	}
	receipt, inspectErr := receiptForArtifact(ctx, discovery, candidate, observed, file, keyring, packageKeyringSHA256)
	after, statErr := file.Stat()
	closeErr := file.Close()
	if inspectErr != nil || statErr != nil || closeErr != nil {
		return provenance.Receipt{}, errors.Join(inspectErr, statErr, closeErr)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return provenance.Receipt{}, fmt.Errorf("%w: downloaded artifact changed during digest/signature inspection", ErrEvidence)
	}
	return receipt, nil
}

func receiptForArtifact(ctx context.Context, discovery *Discovery, candidate syncer.Candidate, observed time.Time, reader io.ReadSeeker, keyring openpgp.KeyRing, packageKeyringSHA256 string) (provenance.Receipt, error) {
	if reader == nil {
		return provenance.Receipt{}, fmt.Errorf("%w: artifact reader is required for %s", ErrEvidence, candidate.SHA256)
	}
	// Signed metadata names the exact package bytes. Hash through the same
	// stable handle that is closed after receipt construction, regardless of
	// format; size-only CAS membership cannot bind a DEB or RPM coordinate to
	// its body. RPM signature verification then reuses this handle.
	if err := verifyCandidateArtifactDigest(ctx, candidate, reader); err != nil {
		return provenance.Receipt{}, err
	}
	if candidate.Format != "rpm" {
		return discovery.Receipt(candidate, observed)
	}
	signatures, err := yumrepo.VerifyEmbeddedRPMSignatures(ctx, reader, keyring, observed)
	if err != nil {
		return provenance.Receipt{}, fmt.Errorf("%w: verify embedded RPM signature for %s: %v", ErrEvidence, candidate.SHA256, err)
	}
	evidence := make([]provenance.RPMSignatureEvidence, len(signatures))
	for i, signature := range signatures {
		evidence[i] = provenance.RPMSignatureEvidence{
			HeaderTag: signature.HeaderTag, HeaderTagID: signature.HeaderTagID,
			PacketSHA256: signature.PacketSHA256, PacketSize: signature.PacketSize,
			PacketVersion: signature.PacketVersion, PublicKeyAlgorithm: signature.PublicKeyAlgorithm,
			HashAlgorithm: signature.HashAlgorithm, IssuerKeyID: signature.IssuerKeyID,
			SignatureCreatedAt: signature.SignatureCreatedAt.UTC().Format(time.RFC3339),
			Coverage:           string(signature.Coverage), SignedBytes: signature.SignedBytes,
			SignerFingerprint: signature.SignerFingerprint, SignerKeyID: signature.SignerKeyID,
			SignerPrimaryFingerprint: signature.SignerPrimaryFingerprint,
			PayloadDigestAlgorithm:   signature.PayloadDigestAlgorithm, PayloadDigest: signature.PayloadDigest,
		}
	}
	return discovery.VerifiedRPMReceipt(candidate, observed, packageKeyringSHA256, evidence)
}

func verifyCandidateArtifactDigest(ctx context.Context, candidate syncer.Candidate, reader io.ReadSeeker) error {
	if ctx == nil {
		return errors.New("upstream: nil artifact verification context")
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("%w: rewind artifact %s for digest verification: %v", ErrEvidence, candidate.SHA256, err)
	}
	hasher := sha256.New()
	written, err := io.CopyBuffer(hasher, &artifactContextReader{ctx: ctx, reader: reader}, make([]byte, 256*1024))
	actual := hex.EncodeToString(hasher.Sum(nil))
	if err != nil || written != candidate.Size || actual != candidate.SHA256 {
		return fmt.Errorf("%w: artifact %s body digest/size mismatch: read=%d want=%d sha256=%s", ErrEvidence, candidate.SHA256, written, candidate.Size, actual)
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("%w: rewind artifact %s after digest verification: %v", ErrEvidence, candidate.SHA256, err)
	}
	return nil
}

type artifactContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *artifactContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func validateMaterializedCandidates(discovery *Discovery) error {
	if discovery == nil || discovery.Candidates == nil {
		return nil
	}
	if len(discovery.Candidates) != discovery.CandidateCount() {
		return fmt.Errorf("%w: discovery candidate set was mutated", ErrInvalidMetadata)
	}
	selected := make(map[string]syncer.Candidate, len(discovery.Candidates))
	for _, candidate := range discovery.Candidates {
		if _, duplicate := selected[candidate.SHA256]; duplicate {
			return fmt.Errorf("%w: discovery candidate set contains duplicates", ErrInvalidMetadata)
		}
		selected[candidate.SHA256] = candidate
	}
	return discovery.ForEachCandidate(func(candidate syncer.Candidate) error {
		if selected[candidate.SHA256] != candidate {
			return fmt.Errorf("%w: discovery candidate set was mutated", ErrInvalidMetadata)
		}
		return nil
	})
}

func commitReceipt(store *provenance.Store, candidate syncer.Candidate, file string, wanted provenance.Receipt) (Downloaded, error) {
	if existing, err := store.Get(candidate.Format, candidate.SHA256); err == nil {
		if !sameReceiptEvidence(existing, wanted) {
			return Downloaded{}, fmt.Errorf("provenance conflict for artifact %s", candidate.SHA256)
		}
		id, err := existing.ID()
		return Downloaded{Candidate: candidate, Path: file, ReceiptID: id}, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return Downloaded{}, err
	}
	id, created, err := store.Put(wanted)
	if err != nil {
		// Another process may have won an identical receipt race. Re-read and
		// accept it even if its observation timestamp differs.
		if existing, readErr := store.Get(candidate.Format, candidate.SHA256); readErr == nil && sameReceiptEvidence(existing, wanted) {
			id, idErr := existing.ID()
			return Downloaded{Candidate: candidate, Path: file, ReceiptID: id}, idErr
		}
		return Downloaded{}, err
	}
	return Downloaded{Candidate: candidate, Path: file, ReceiptID: id, NewReceipt: created}, nil
}

func sameReceiptEvidence(left, right provenance.Receipt) bool {
	if left.Format != right.Format || left.ArtifactSHA256 != right.ArtifactSHA256 ||
		left.ArtifactSize != right.ArtifactSize {
		return false
	}
	if left.Format == "deb" {
		// The artifact-keyed ledger retains the first valid signed
		// observation. Discovery.ValidateEvidence already authenticated the
		// current Packages/Release chain, so URL and metadata rotation do not
		// create a second identity for the same immutable DEB bytes.
		return left.DEB != nil && right.DEB != nil && left.RPM == nil && right.RPM == nil
	}
	if left.RPM == nil || right.RPM == nil || left.DEB != nil || right.DEB != nil {
		return false
	}
	if left.RPM.OriginalRPMSHA != left.ArtifactSHA256 || right.RPM.OriginalRPMSHA != right.ArtifactSHA256 ||
		left.RPM.SignaturePolicy != right.RPM.SignaturePolicy {
		return false
	}
	if !validRPMReceiptSchema(left.Schema) || !validRPMReceiptSchema(right.Schema) {
		return false
	}
	leftHasBody, rightHasBody := left.Schema != provenance.LegacySchema, right.Schema != provenance.LegacySchema
	if !leftHasBody && !rightHasBody {
		return len(left.RPM.EmbeddedSignatures) == 0 && len(right.RPM.EmbeddedSignatures) == 0 &&
			left.RPM.SignatureVerification == "" && right.RPM.SignatureVerification == ""
	}
	if leftHasBody && rightHasBody {
		return sameRPMEmbeddedSignatureBodies(left.RPM.EmbeddedSignatures, right.RPM.EmbeddedSignatures)
	}
	// A valid v1 receipt has no inspected packet fields. Cross-version replay
	// is symmetric: the current v3 side has already verified the exact body,
	// while the first canonical observation remains byte-for-byte unchanged.
	current := left.RPM
	if !leftHasBody {
		current = right.RPM
	}
	return len(current.EmbeddedSignatures) > 0
}

func validRPMReceiptSchema(schema string) bool {
	return schema == provenance.Schema || schema == provenance.PreviousSchema || schema == provenance.LegacySchema
}

func sameRPMEmbeddedSignatureBodies(left, right []provenance.RPMSignatureEvidence) bool {
	if len(left) == 0 || len(left) != len(right) {
		return false
	}
	stripTrust := func(value provenance.RPMSignatureEvidence) provenance.RPMSignatureEvidence {
		value.SignatureCreatedAt = ""
		value.Coverage = ""
		value.SignedBytes = 0
		value.SignerFingerprint = ""
		value.SignerKeyID = ""
		value.SignerPrimaryFingerprint = ""
		value.PayloadDigestAlgorithm = ""
		value.PayloadDigest = ""
		return value
	}
	for index := range left {
		if !reflect.DeepEqual(stripTrust(left[index]), stripTrust(right[index])) {
			return false
		}
	}
	return true
}
