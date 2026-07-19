package provenance

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStorePutFailsClosedOnDirectorySyncAndReplayConverges(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	store := NewStore(stateDir)
	injected := errors.New("injected provenance directory sync failure")
	calls := 0
	store.directorySync = func(string) error {
		calls++
		return injected
	}
	receipt := NewDEB(hashA, 42, "https://example.invalid/example.deb", time.Unix(1, 0).UTC(), DEBProof{
		PackagesEntrySHA256: hashB, PackagesEvidenceSHA256: hashC,
		SignedReleaseSHA256: hashA, SignedReleaseKind: "InRelease",
	})
	if _, created, err := store.Put(receipt); !errors.Is(err, injected) || created {
		t.Fatalf("directory sync failure was hidden: created=%t err=%v", created, err)
	}
	coordinate := filepath.Join(stateDir, "provenance", "deb", hashA+".json")
	if _, err := os.Stat(coordinate); err != nil {
		t.Fatalf("post-link uncertain receipt is not inspectable: %v", err)
	}
	store.directorySync = syncProvenanceDirectory
	if _, created, err := store.Put(receipt); err != nil || created {
		t.Fatalf("replay did not converge through existing receipt: created=%t err=%v", created, err)
	}
	if calls != 1 {
		t.Fatalf("injected sync calls=%d, want 1", calls)
	}
}

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hashC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestRPMAndDEBProofsAreStructurallyDifferent(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	rpm := NewRPM(hashA, 42, "https://example.com/pkg.rpm", now, RPMProof{
		IndexURL: "https://example.com/repodata/primary.xml.zst", IndexSHA256: hashB,
		IndexSize: 12, OriginalRPMSHA: hashA, SignaturePolicy: "preserve-upstream",
		EmbeddedSignatures: []RPMSignatureEvidence{{
			HeaderTag: "RPMSIGTAG_RSA", HeaderTagID: 268, PacketSHA256: hashC, PacketSize: 256,
			PacketVersion: 4, PublicKeyAlgorithm: 1, HashAlgorithm: 8, IssuerKeyID: "0123456789abcdef",
			SignatureCreatedAt: "2026-07-11T11:00:00Z", Coverage: "header+payload-digest", SignedBytes: 4096,
			SignerFingerprint: "1111111111111111111111110123456789abcdef", SignerKeyID: "0123456789abcdef",
			SignerPrimaryFingerprint: "1111111111111111111111110123456789abcdef",
			PayloadDigestAlgorithm:   "SHA-256", PayloadDigest: hashA,
		}}, SignatureVerification: "verified", PackageKeyringSHA256: hashB,
	})
	if err := rpm.Validate(); err != nil {
		t.Fatal(err)
	}
	deb := NewDEB(hashA, 42, "https://example.com/pkg.deb", now, DEBProof{
		PackagesEntrySHA256: hashB, PackagesEvidenceSHA256: hashC,
		SignedReleaseSHA256: hashA, SignedReleaseKind: "InRelease",
	})
	if err := deb.Validate(); err != nil {
		t.Fatal(err)
	}
	rpm.DEB = deb.DEB
	if err := rpm.Validate(); err == nil || !strings.Contains(err.Error(), "only the rpm") {
		t.Fatalf("mixed proof accepted: %v", err)
	}
}

func TestStoreConcurrentWritersNeverOverwrite(t *testing.T) {
	base := NewDEB(hashA, 42, "https://example.com/pkg.deb", time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC), DEBProof{
		PackagesEntrySHA256: hashB, PackagesEvidenceSHA256: hashC,
		SignedReleaseSHA256: hashA, SignedReleaseKind: "InRelease",
	})
	other := base
	other.ObservedAt = base.ObservedAt.Add(time.Second)
	store := NewStore(t.TempDir())
	receipts := []Receipt{base, other}
	results := make(chan error, len(receipts))
	var wg sync.WaitGroup
	for _, receipt := range receipts {
		wg.Add(1)
		go func(value Receipt) {
			defer wg.Done()
			_, _, err := store.Put(value)
			results <- err
		}(receipt)
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case strings.Contains(err.Error(), "conflict"):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	if _, err := store.Get("deb", hashA); err != nil {
		t.Fatalf("winning receipt is corrupt: %v", err)
	}
}

func TestReceiptRejectsSecretsAndRPMResigning(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	receipt := NewRPM(hashA, 1, "https://user:secret@example.com/pkg.rpm", now, RPMProof{
		IndexURL: "https://example.com/primary", IndexSHA256: hashB, OriginalRPMSHA: hashA,
		SignaturePolicy: "preserve-upstream", EmbeddedSignatures: []RPMSignatureEvidence{{
			HeaderTag: "RPMSIGTAG_DSA", HeaderTagID: 267, PacketSHA256: hashC, PacketSize: 64,
			PacketVersion: 4, PublicKeyAlgorithm: 17, HashAlgorithm: 2,
			SignatureCreatedAt: "2026-07-11T11:00:00Z", Coverage: "header+payload-digest", SignedBytes: 4096,
			SignerFingerprint: "1111111111111111111111110123456789abcdef", SignerKeyID: "0123456789abcdef",
			SignerPrimaryFingerprint: "1111111111111111111111110123456789abcdef",
			PayloadDigestAlgorithm:   "SHA-256", PayloadDigest: hashA,
		}}, SignatureVerification: "verified", PackageKeyringSHA256: hashB,
	})
	if err := receipt.Validate(); err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("credential URL accepted: %v", err)
	}
	receipt.UpstreamURL = "https://example.com/pkg.rpm"
	receipt.RPM.OriginalRPMSHA = hashB
	if err := receipt.Validate(); err == nil || !strings.Contains(err.Error(), "preserve") {
		t.Fatalf("rewritten RPM accepted: %v", err)
	}
}

func TestRPMReceiptRejectsMissingMalformedOrUnboundVerifiedSignatureEvidence(t *testing.T) {
	proof := RPMProof{
		IndexURL: "https://example.com/primary", IndexSHA256: hashB, OriginalRPMSHA: hashA,
		SignaturePolicy: "preserve-upstream", SignatureVerification: "verified", PackageKeyringSHA256: hashB,
	}
	receipt := NewRPM(hashA, 1, "https://example.com/pkg.rpm", time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC), proof)
	if err := receipt.Validate(); err == nil || !strings.Contains(err.Error(), "embedded signature") {
		t.Fatalf("missing embedded signature accepted: %v", err)
	}
	receipt.RPM.EmbeddedSignatures = []RPMSignatureEvidence{{
		HeaderTag: "RPMSIGTAG_RSA", HeaderTagID: 268, PacketSHA256: hashC, PacketSize: 256,
		PacketVersion: 4, PublicKeyAlgorithm: 17, HashAlgorithm: 8,
		SignatureCreatedAt: "2026-07-11T11:00:00Z", Coverage: "header+payload-digest", SignedBytes: 4096,
		SignerFingerprint: "1111111111111111111111110123456789abcdef", SignerKeyID: "0123456789abcdef",
		SignerPrimaryFingerprint: "1111111111111111111111110123456789abcdef",
		PayloadDigestAlgorithm:   "SHA-256", PayloadDigest: hashA,
	}}
	if err := receipt.Validate(); err == nil || !strings.Contains(err.Error(), "RSA") {
		t.Fatalf("mismatched modern signature tag accepted: %v", err)
	}
	receipt.RPM.EmbeddedSignatures[0].PublicKeyAlgorithm = 1
	receipt.RPM.EmbeddedSignatures[0].SignerKeyID = "fedcba9876543210"
	if err := receipt.Validate(); err == nil || !strings.Contains(err.Error(), "low 64 bits") {
		t.Fatalf("unbound signer identity accepted: %v", err)
	}
}

func TestPreviousV2RPMReceiptRemainsDecodableWithoutInventingSignerTrust(t *testing.T) {
	previous := []byte(`{"schema":"sow-provenance/v2","format":"rpm","artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact_size":42,"upstream_url":"https://example.com/pkg.rpm","observed_at":"2026-07-11T12:00:00Z","rpm":{"index_url":"https://example.com/repodata/primary.xml.zst","index_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","index_size":12,"original_rpm_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature_policy":"preserve-upstream","embedded_signatures":[{"header_tag":"RPMSIGTAG_RSA","header_tag_id":268,"packet_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","packet_size":256,"packet_version":4,"public_key_algorithm":1,"hash_algorithm":8,"issuer_key_id":"0123456789abcdef"}],"signature_verification":"not-performed"}}` + "\n")
	receipt, err := Decode(previous)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != PreviousSchema || receipt.RPM == nil || receipt.RPM.PackageKeyringSHA256 != "" || receipt.RPM.EmbeddedSignatures[0].SignerFingerprint != "" {
		t.Fatalf("v2 receipt was assigned signer trust: %#v", receipt)
	}
	canonical, err := receipt.CanonicalJSON()
	if err != nil || !bytes.Equal(canonical, previous) {
		t.Fatalf("v2 canonical receipt changed: %v\n%s", err, canonical)
	}
}

func TestLegacyRPMReceiptRemainsDecodableWithoutInventingSignatureVerification(t *testing.T) {
	legacy := []byte(`{"schema":"sow-provenance/v1","format":"rpm","artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact_size":42,"upstream_url":"https://example.com/pkg.rpm","observed_at":"2026-07-11T12:00:00Z","rpm":{"index_url":"https://example.com/repodata/primary.xml.zst","index_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","index_size":12,"original_rpm_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature_policy":"preserve-upstream"}}` + "\n")
	receipt, err := Decode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != LegacySchema || receipt.RPM == nil || len(receipt.RPM.EmbeddedSignatures) != 0 || receipt.RPM.SignatureVerification != "" {
		t.Fatalf("legacy receipt was assigned new verification evidence: %#v", receipt)
	}
	canonical, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, legacy) || bytes.Contains(canonical, []byte("signature_verification")) || bytes.Contains(canonical, []byte("embedded_signatures")) {
		t.Fatalf("legacy canonical receipt changed: %s", canonical)
	}
}

func TestStoreIsIdempotentAndDetectsConflicts(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	receipt := NewDEB(hashA, 42, "https://example.com/pkg.deb", now, DEBProof{
		PackagesEntrySHA256: hashB, PackagesEvidenceSHA256: hashC,
		SignedReleaseSHA256: hashA, SignedReleaseKind: "InRelease",
	})
	store := NewStore(t.TempDir())
	id, created, err := store.Put(receipt)
	if err != nil || !created || id == "" {
		t.Fatalf("first put: id=%s created=%v err=%v", id, created, err)
	}
	second, created, err := store.Put(receipt)
	if err != nil || created || second != id {
		t.Fatalf("idempotent put: id=%s created=%v err=%v", second, created, err)
	}
	loaded, err := store.Get("deb", hashA)
	if err != nil || loaded.ArtifactSHA256 != hashA {
		t.Fatalf("get: %#v %v", loaded, err)
	}
	receipt.ArtifactSize++
	if _, _, err := store.Put(receipt); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("conflicting receipt accepted: %v", err)
	}
}

func TestLegacyAdoptionReceiptJSONLIsStrictDeterministicAndSorted(t *testing.T) {
	now := time.Date(2026, 7, 12, 1, 2, 3, 0, time.UTC)
	receipt := LegacyAdoptionReceipt{
		Schema: LegacyAdoptionSchema, Format: "rpm", Repo: "yum_legacy",
		SourcePath: "yum/test/pkg.rpm", CanonicalPath: "yum/test/Packages/p/pkg.rpm", ArtifactSize: 42,
		ArtifactSHA256: hashA, Pool: "public", AdoptedAt: now,
		ConfigCommit: strings.Repeat("1", 40),
	}
	first, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	second, err := receipt.CanonicalJSON()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("legacy receipt is not deterministic: %v", err)
	}
	decoded, err := DecodeLegacyAdoption(first)
	if err != nil || decoded != receipt {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	var ledger bytes.Buffer
	if err := WriteLegacyAdoption(&ledger, receipt); err != nil {
		t.Fatal(err)
	}
	next := receipt
	next.SourcePath = "yum/test/z.rpm"
	next.CanonicalPath = "yum/test/Packages/z/z.rpm"
	if err := WriteLegacyAdoption(&ledger, next); err != nil {
		t.Fatal(err)
	}
	reader := NewLegacyAdoptionReader(&ledger)
	if _, err := reader.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("ledger EOF=%v", err)
	}
	bad := receipt
	bad.SourcePath = "../escape.rpm"
	if _, err := bad.CanonicalJSON(); err == nil {
		t.Fatal("legacy receipt accepted path escape")
	}
	bad = receipt
	bad.CanonicalPath = "../escape.rpm"
	if _, err := bad.CanonicalJSON(); err == nil {
		t.Fatal("legacy receipt accepted canonical path escape")
	}
	bad = receipt
	bad.CanonicalPath = "."
	if _, err := bad.CanonicalJSON(); err == nil {
		t.Fatal("legacy receipt accepted root pseudo-path")
	}
	bad = receipt
	bad.ConfigCommit = strings.Repeat("x", 40)
	if _, err := bad.CanonicalJSON(); err == nil {
		t.Fatal("legacy receipt accepted malformed config commit")
	}
}

func TestLegacyAdoptionReceiptDecodesPreCanonicalPathLedger(t *testing.T) {
	legacy := []byte(`{"schema":"sow-legacy-adoption/v1","format":"rpm","repo":"yum_legacy","source_path":"yum/test/Packages/p/pkg.rpm","artifact_size":42,"artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pool":"public","adopted_at":"2026-07-12T01:02:03Z","config_commit":"1111111111111111111111111111111111111111"}` + "\n")
	receipt, err := DecodeLegacyAdoption(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.CanonicalPath != receipt.SourcePath {
		t.Fatalf("legacy canonical path=%q source=%q", receipt.CanonicalPath, receipt.SourcePath)
	}
	receipt.CanonicalPath = ""
	if err := receipt.Validate(); err != nil {
		t.Fatalf("pre-canonical in-memory receipt no longer validates: %v", err)
	}
}

func TestLegacyIndexPruneReceiptIsStrictAndSorted(t *testing.T) {
	receipt := LegacyIndexPruneReceipt{
		Schema: LegacyIndexPruneSchema, Repo: "yum-pgdg-13-el10",
		Path: "yum/pgdg/13/redhat/rhel-10-x86_64/missing.rpm", Name: "missing", Version: "1-1", Arch: "x86_64",
		ArtifactSize: 42, ArtifactSHA256: strings.Repeat("a", 64), Reason: "indexed-body-missing",
		ConfirmationSHA256: strings.Repeat("b", 64), RecordedAt: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC),
		BaselineCommit: strings.Repeat("c", 40),
	}
	first, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeLegacyIndexPrune(first)
	if err != nil || decoded != receipt {
		t.Fatalf("decode=%+v err=%v", decoded, err)
	}
	var ledger bytes.Buffer
	if err := WriteLegacyIndexPrune(&ledger, receipt); err != nil {
		t.Fatal(err)
	}
	next := receipt
	next.Path = "yum/pgdg/13/redhat/rhel-10-x86_64/z.rpm"
	if err := WriteLegacyIndexPrune(&ledger, next); err != nil {
		t.Fatal(err)
	}
	reader := NewLegacyIndexPruneReader(&ledger)
	if _, err := reader.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("ledger EOF=%v", err)
	}
	next.Path = receipt.Path
	var duplicate bytes.Buffer
	_ = WriteLegacyIndexPrune(&duplicate, receipt)
	_ = WriteLegacyIndexPrune(&duplicate, next)
	duplicateReader := NewLegacyIndexPruneReader(&duplicate)
	_, _ = duplicateReader.Next()
	if _, err := duplicateReader.Next(); err == nil || !strings.Contains(err.Error(), "strictly sorted") {
		t.Fatalf("duplicate path accepted: %v", err)
	}

	next.Path = "yum/pgdg/13/redhat/rhel-10-x86_64/z.rpm"
	identities := []LegacyIndexPruneIdentity{next.Identity(), receipt.Identity()}
	digest, err := LegacyIndexPruneSetSHA256(identities)
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := LegacyIndexPruneSetSHA256([]LegacyIndexPruneIdentity{receipt.Identity(), next.Identity()})
	if err != nil || reversed != digest {
		t.Fatalf("set digest=%q reversed=%q err=%v", digest, reversed, err)
	}
	if _, err := LegacyIndexPruneSetSHA256([]LegacyIndexPruneIdentity{receipt.Identity(), receipt.Identity()}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate confirmation identity accepted: %v", err)
	}
	changed := receipt.Identity()
	changed.ArtifactSize++
	changedDigest, err := LegacyIndexPruneSetSHA256([]LegacyIndexPruneIdentity{changed, next.Identity()})
	if err != nil || changedDigest == digest {
		t.Fatalf("changed set digest=%q original=%q err=%v", changedDigest, digest, err)
	}
	unsafe := receipt.Identity()
	unsafe.Name = "missing\tforged"
	if _, err := LegacyIndexPruneSetSHA256([]LegacyIndexPruneIdentity{unsafe}); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("delimiter-bearing identity accepted: %v", err)
	}
	unsafeReceipt := receipt
	unsafeReceipt.Version = "1\nforged"
	if err := unsafeReceipt.Validate(); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("delimiter-bearing receipt accepted: %v", err)
	}
}
