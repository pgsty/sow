// Package upstream discovers and synchronizes package artifacts from signed
// APT and signed/checksummed YUM repository metadata. It deliberately stops at the
// verified download/provenance boundary: repository view generation remains
// the responsibility of aptrepo and yumrepo.
package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/syncer"
)

var (
	ErrUnsafeURL          = errors.New("upstream: unsafe URL")
	ErrMetadataTooLarge   = errors.New("upstream: metadata exceeds configured limit")
	ErrInvalidMetadata    = errors.New("upstream: invalid repository metadata")
	ErrSignature          = errors.New("upstream: metadata signature verification failed")
	ErrConflictingPackage = errors.New("upstream: conflicting package metadata")
	ErrEvidence           = errors.New("upstream: provenance evidence is missing or corrupt")
)

// Limits bounds both allocations made by parsers and the amount of expanded
// metadata accepted from a compressed index. Zero values receive conservative
// defaults suitable for large public package repositories.
type Limits struct {
	ReleaseBytes           int64
	RepomdBytes            int64
	SignatureBytes         int64
	IndexCompressedBytes   int64
	IndexUncompressedBytes int64
	StanzaBytes            int
	XMLDepth               int
	XMLTokenBytes          int
	PackageCount           int
	XZDictionaryBytes      int
	ZstdMemoryBytes        uint64
}

func (l Limits) withDefaults() Limits {
	if l.ReleaseBytes <= 0 {
		l.ReleaseBytes = 16 << 20
	}
	if l.RepomdBytes <= 0 {
		l.RepomdBytes = 16 << 20
	}
	if l.SignatureBytes <= 0 {
		l.SignatureBytes = 4 << 20
	}
	if l.IndexCompressedBytes <= 0 {
		l.IndexCompressedBytes = 4 << 30
	}
	if l.IndexUncompressedBytes <= 0 {
		l.IndexUncompressedBytes = 8 << 30
	}
	if l.StanzaBytes <= 0 {
		l.StanzaBytes = 8 << 20
	}
	if l.XMLDepth <= 0 {
		l.XMLDepth = 64
	}
	if l.XMLTokenBytes <= 0 {
		l.XMLTokenBytes = 2 << 20
	}
	if l.PackageCount <= 0 {
		l.PackageCount = 500_000
	}
	if l.XZDictionaryBytes <= 0 {
		l.XZDictionaryBytes = 64 << 20
	}
	if l.ZstdMemoryBytes == 0 {
		l.ZstdMemoryBytes = 64 << 20
	}
	return l
}

func (l Limits) validate() error {
	if l.ReleaseBytes < 0 || l.RepomdBytes < 0 || l.SignatureBytes < 0 ||
		l.IndexCompressedBytes < 0 || l.IndexUncompressedBytes < 0 ||
		l.StanzaBytes < 0 || l.XMLDepth < 0 || l.XMLTokenBytes < 0 ||
		l.PackageCount < 0 || l.XZDictionaryBytes < 0 {
		return fmt.Errorf("%w: resource limits cannot be negative", ErrInvalidMetadata)
	}
	l = l.withDefaults()
	if l.ReleaseBytes < 1 || l.RepomdBytes < 1 || l.SignatureBytes < 1 ||
		l.IndexCompressedBytes < 1 || l.IndexUncompressedBytes < 1 ||
		l.StanzaBytes < 1024 || l.XMLDepth < 4 || l.XMLTokenBytes < 1024 ||
		l.PackageCount < 1 || l.XZDictionaryBytes < 4096 ||
		l.ZstdMemoryBytes < 1<<20 {
		return fmt.Errorf("%w: invalid resource limits", ErrInvalidMetadata)
	}
	if l.ReleaseBytes > 1<<30 || l.RepomdBytes > 1<<30 || l.SignatureBytes > 16<<20 ||
		l.IndexCompressedBytes > 64<<30 || l.IndexUncompressedBytes > 128<<30 ||
		l.StanzaBytes > 64<<20 || l.XMLDepth > 256 || l.XMLTokenBytes > 64<<20 ||
		l.PackageCount > 2_000_000 || l.XZDictionaryBytes > 1<<30 ||
		l.ZstdMemoryBytes > 1<<30 {
		return fmt.Errorf("%w: resource limits exceed safe parser bounds", ErrInvalidMetadata)
	}
	return nil
}

// Evidence is one exact upstream metadata object preserved locally. SHA256
// always hashes the bytes at Path, not an expanded or normalized form.
type Evidence struct {
	Kind     string
	URL      string
	Path     string
	SHA256   string
	Size     int64
	Verified bool
}

type candidateProof struct {
	rpm *provenance.RPMProof
	deb *provenance.DEBProof
}

// Discovery is an immutable, verified projection of one metadata snapshot.
// Candidates are package bodies only. Evidence retains the metadata that
// authenticated those candidates and can be archived with the state commit.
type Discovery struct {
	Format string
	// Candidates is populated only by the compatibility DiscoverAPT and
	// DiscoverYUM wrappers. Production callers use the streaming constructors
	// and ForEachCandidate, which keep this slice nil even for very large repos.
	Candidates []syncer.Candidate
	Evidence   []Evidence
	store      *candidateStore
	count      int
	evidence   map[string]Evidence
}

func newDiscovery(format, workDir string) (*Discovery, error) {
	store, err := newCandidateStore(workDir)
	if err != nil {
		return nil, err
	}
	return &Discovery{Format: format, store: store}, nil
}

// CandidateCount reports the number of unique authenticated package bodies
// without materializing them in memory.
func (d *Discovery) CandidateCount() int {
	if d == nil {
		return 0
	}
	return d.count
}

// ForEachCandidate iterates candidates in SHA-256 order from the sealed disk
// spool. The callback must not retain candidates unless the retained set is a
// deliberate change set.
func (d *Discovery) ForEachCandidate(fn func(syncer.Candidate) error) error {
	return d.ForEachCandidateContext(context.Background(), fn)
}

// ForEachCandidateContext is ForEachCandidate with prompt cancellation of the
// underlying SQLite scan.
func (d *Discovery) ForEachCandidateContext(ctx context.Context, fn func(syncer.Candidate) error) error {
	if d == nil || d.store == nil || fn == nil {
		return fmt.Errorf("%w: discovery and candidate callback are required", ErrInvalidMetadata)
	}
	if ctx == nil {
		return errors.New("upstream: nil candidate iteration context")
	}
	return d.store.forEachContext(ctx, func(record candidateRecord) error { return fn(record.Candidate) })
}

func (d *Discovery) forEachRecord(fn func(candidateRecord) error) error {
	if d == nil || d.store == nil || fn == nil {
		return fmt.Errorf("%w: discovery candidate store is unavailable", ErrInvalidMetadata)
	}
	return d.store.forEach(fn)
}

// Close releases and removes the rebuildable candidate spool. Evidence files
// remain because they are committed as canonical provenance by the caller.
func (d *Discovery) Close() error {
	if d == nil || d.store == nil {
		return nil
	}
	err := d.store.close()
	d.store = nil
	return err
}

// Receipt constructs the format-specific provenance entry for a candidate
// from this exact discovery. It refuses candidates not present in the signed
// snapshot, preventing callers from manufacturing an unrelated receipt.
func (d *Discovery) Receipt(candidate syncer.Candidate, observed time.Time) (provenance.Receipt, error) {
	if d == nil || d.store == nil {
		return provenance.Receipt{}, fmt.Errorf("%w: empty discovery", ErrInvalidMetadata)
	}
	if err := candidate.Validate(); err != nil {
		return provenance.Receipt{}, err
	}
	record, err := d.store.get(candidate.SHA256)
	if errors.Is(err, os.ErrNotExist) {
		return provenance.Receipt{}, fmt.Errorf("%w: package %s is not in discovery", ErrInvalidMetadata, candidate.SHA256)
	}
	if err != nil {
		return provenance.Receipt{}, err
	}
	if record.Candidate != candidate || candidate.Format != d.Format {
		return provenance.Receipt{}, fmt.Errorf("%w: package %s is not in discovery", ErrInvalidMetadata, candidate.SHA256)
	}
	return d.receipt(record, observed, "", nil)
}

// VerifiedRPMReceipt constructs a v3 RPM receipt only from cryptographically
// verified package evidence and the digest of the exact public trust bundle.
func (d *Discovery) VerifiedRPMReceipt(candidate syncer.Candidate, observed time.Time, packageKeyringSHA256 string, rpmSignatures []provenance.RPMSignatureEvidence) (provenance.Receipt, error) {
	if d == nil || d.store == nil {
		return provenance.Receipt{}, fmt.Errorf("%w: empty discovery", ErrInvalidMetadata)
	}
	if candidate.Format != "rpm" {
		return provenance.Receipt{}, fmt.Errorf("%w: verified RPM receipt requires an RPM candidate", ErrInvalidMetadata)
	}
	if err := candidate.Validate(); err != nil {
		return provenance.Receipt{}, err
	}
	record, err := d.store.get(candidate.SHA256)
	if errors.Is(err, os.ErrNotExist) {
		return provenance.Receipt{}, fmt.Errorf("%w: package %s is not in discovery", ErrInvalidMetadata, candidate.SHA256)
	}
	if err != nil {
		return provenance.Receipt{}, err
	}
	if record.Candidate != candidate || candidate.Format != d.Format {
		return provenance.Receipt{}, fmt.Errorf("%w: package %s is not in discovery", ErrInvalidMetadata, candidate.SHA256)
	}
	return d.receipt(record, observed, packageKeyringSHA256, rpmSignatures)
}

func (d *Discovery) receipt(record candidateRecord, observed time.Time, packageKeyringSHA256 string, rpmSignatures []provenance.RPMSignatureEvidence) (provenance.Receipt, error) {
	candidate := record.Candidate
	proof := record.Proof
	var receipt provenance.Receipt
	switch d.Format {
	case "rpm":
		if proof.rpm == nil {
			return provenance.Receipt{}, fmt.Errorf("%w: missing RPM proof", ErrInvalidMetadata)
		}
		complete := *proof.rpm
		complete.EmbeddedSignatures = append([]provenance.RPMSignatureEvidence(nil), rpmSignatures...)
		complete.SignatureVerification = "verified"
		complete.PackageKeyringSHA256 = packageKeyringSHA256
		receipt = provenance.NewRPM(candidate.SHA256, candidate.Size, candidate.URL, observed, complete)
	case "deb":
		if proof.deb == nil {
			return provenance.Receipt{}, fmt.Errorf("%w: missing DEB proof", ErrInvalidMetadata)
		}
		receipt = provenance.NewDEB(candidate.SHA256, candidate.Size, candidate.URL, observed, *proof.deb)
	default:
		return provenance.Receipt{}, fmt.Errorf("%w: unsupported discovery format %q", ErrInvalidMetadata, d.Format)
	}
	if err := receipt.Validate(); err != nil {
		return provenance.Receipt{}, err
	}
	return receipt, nil
}

// ValidateEvidence re-hashes the exact metadata objects that root a discovery.
// Executor invokes it immediately before committing any receipt so deletion or
// mutation between discovery and execution cannot create an unverifiable
// provenance entry.
func (d *Discovery) ValidateEvidence() error {
	if d == nil || d.store == nil || len(d.evidence) == 0 {
		return fmt.Errorf("%w: discovery has no sealed evidence", ErrEvidence)
	}
	keys := make([]string, 0, len(d.evidence))
	for key := range d.evidence {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		evidence := d.evidence[key]
		if !evidence.Verified {
			return fmt.Errorf("%w: %s is not signature/checksum verified", ErrEvidence, evidence.Kind)
		}
		pathInfo, err := os.Lstat(evidence.Path)
		if err != nil {
			return fmt.Errorf("%w: inspect %s: %v", ErrEvidence, evidence.Kind, err)
		}
		if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Size() != evidence.Size {
			return fmt.Errorf("%w: invalid %s file", ErrEvidence, evidence.Kind)
		}
		file, err := os.Open(evidence.Path)
		if err != nil {
			return fmt.Errorf("%w: open %s: %v", ErrEvidence, evidence.Kind, err)
		}
		openedInfo, err := file.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
			_ = file.Close()
			return fmt.Errorf("%w: %s changed while opening", ErrEvidence, evidence.Kind)
		}
		hash := sha256.New()
		written, copyErr := io.CopyBuffer(hash, file, make([]byte, 256*1024))
		closeErr := file.Close()
		actual := hex.EncodeToString(hash.Sum(nil))
		afterInfo, statErr := os.Lstat(evidence.Path)
		if copyErr != nil || closeErr != nil || statErr != nil || !os.SameFile(pathInfo, afterInfo) ||
			afterInfo.Size() != pathInfo.Size() || !afterInfo.ModTime().Equal(pathInfo.ModTime()) ||
			written != evidence.Size || actual != evidence.SHA256 {
			return fmt.Errorf("%w: hash/size mismatch for %s", ErrEvidence, evidence.Kind)
		}
	}
	return d.validateEvidenceBindings()
}

func (d *Discovery) validateEvidenceBindings() error {
	kinds := make(map[string][]Evidence)
	for _, evidence := range d.evidence {
		kinds[evidence.Kind] = append(kinds[evidence.Kind], evidence)
	}
	containsHash := func(kind, hash string) bool {
		for _, evidence := range kinds[kind] {
			if evidence.SHA256 == hash {
				return true
			}
		}
		return false
	}
	switch d.Format {
	case "deb":
		if len(kinds["apt-inrelease"]) == 0 &&
			(len(kinds["apt-release"]) == 0 || len(kinds["apt-release-signature"]) == 0) {
			return fmt.Errorf("%w: APT signature root is incomplete", ErrEvidence)
		}
		return d.forEachRecord(func(record candidateRecord) error {
			proof := record.Proof
			if proof.deb == nil || !containsHash("apt-packages", proof.deb.PackagesEvidenceSHA256) {
				return fmt.Errorf("%w: DEB %s lacks Packages evidence", ErrEvidence, record.Candidate.SHA256)
			}
			kind := "apt-inrelease"
			if proof.deb.SignedReleaseKind == "Release+Release.gpg" {
				kind = "apt-release"
			}
			if !containsHash(kind, proof.deb.SignedReleaseSHA256) {
				return fmt.Errorf("%w: DEB %s lacks signed Release evidence", ErrEvidence, record.Candidate.SHA256)
			}
			return nil
		})
	case "rpm":
		if len(kinds["yum-repomd"]) != 1 || len(kinds["yum-repomd-signature"]) != 1 {
			return fmt.Errorf("%w: YUM signed repomd evidence is incomplete", ErrEvidence)
		}
		return d.forEachRecord(func(record candidateRecord) error {
			proof := record.Proof
			if proof.rpm == nil || !containsHash("yum-primary", proof.rpm.IndexSHA256) {
				return fmt.Errorf("%w: RPM %s lacks primary evidence", ErrEvidence, record.Candidate.SHA256)
			}
			return nil
		})
	default:
		return fmt.Errorf("%w: unsupported discovery format %q", ErrEvidence, d.Format)
	}
}

func sealEvidence(discovery *Discovery) error {
	if discovery == nil || len(discovery.Evidence) == 0 {
		return fmt.Errorf("%w: no evidence", ErrEvidence)
	}
	discovery.evidence = make(map[string]Evidence, len(discovery.Evidence))
	for _, evidence := range discovery.Evidence {
		if evidence.Kind == "" || evidence.Path == "" || evidence.Size < 0 || !validSHA256(evidence.SHA256) {
			return fmt.Errorf("%w: malformed evidence record", ErrEvidence)
		}
		parsed, err := url.Parse(strings.TrimSpace(evidence.URL))
		if err != nil || validateHTTPURL(parsed) != nil {
			return fmt.Errorf("%w: evidence URL is unsafe", ErrEvidence)
		}
		key := evidence.Kind + "\x00" + evidence.SHA256
		if prior, exists := discovery.evidence[key]; exists && prior != evidence {
			return fmt.Errorf("%w: conflicting evidence %s", ErrEvidence, evidence.Kind)
		}
		discovery.evidence[key] = evidence
	}
	return discovery.ValidateEvidence()
}
