package upstream

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/syncer"
)

func TestCandidateStoreChoosesRPMProofIndependentlyOfDiscoveryOrder(t *testing.T) {
	candidate := syncer.Candidate{
		Format: "rpm", Name: "package", Version: "1.0-1", Arch: "x86_64",
		URL:  "https://packages.example.invalid/package-1.0-1.x86_64.rpm",
		Size: 7, SHA256: strings.Repeat("a", 64),
	}
	proofs := []candidateProof{
		{rpm: &provenance.RPMProof{
			IndexURL:    "https://packages.example.invalid/repodata/primary-z.xml.zst",
			IndexSHA256: strings.Repeat("f", 64), IndexSize: 200,
			OriginalRPMSHA: candidate.SHA256, SignaturePolicy: "preserve-upstream",
		}},
		{rpm: &provenance.RPMProof{
			IndexURL:    "https://packages.example.invalid/repodata/primary-a.xml.zst",
			IndexSHA256: strings.Repeat("1", 64), IndexSize: 100,
			OriginalRPMSHA: candidate.SHA256, SignaturePolicy: "preserve-upstream",
		}},
	}

	forward := storedCandidateProof(t, candidate, proofs)
	reverse := storedCandidateProof(t, candidate, []candidateProof{proofs[1], proofs[0]})
	if !reflect.DeepEqual(forward, reverse) {
		t.Fatalf("RPM proof depends on discovery order: forward=%+v reverse=%+v", forward.rpm, reverse.rpm)
	}
	if !reflect.DeepEqual(forward, proofs[1]) {
		t.Fatalf("candidate spool did not retain the canonical proof: got=%+v want=%+v", forward.rpm, proofs[1].rpm)
	}
}

func TestCandidateStoreBreaksEqualAPTIndexTiesDeterministically(t *testing.T) {
	candidate := syncer.Candidate{
		Format: "deb", Name: "package", Version: "1.0-1", Arch: "amd64",
		URL:  "https://packages.example.invalid/package_1.0-1_amd64.deb",
		Size: 7, SHA256: strings.Repeat("a", 64),
	}
	proofs := []candidateProof{
		{deb: &provenance.DEBProof{
			PackagesEntrySHA256: strings.Repeat("f", 64), PackagesEvidenceSHA256: strings.Repeat("2", 64),
			SignedReleaseSHA256: strings.Repeat("e", 64), SignedReleaseKind: "InRelease",
		}},
		{deb: &provenance.DEBProof{
			PackagesEntrySHA256: strings.Repeat("1", 64), PackagesEvidenceSHA256: strings.Repeat("2", 64),
			SignedReleaseSHA256: strings.Repeat("3", 64), SignedReleaseKind: "InRelease",
		}},
	}

	forward := storedCandidateProof(t, candidate, proofs)
	reverse := storedCandidateProof(t, candidate, []candidateProof{proofs[1], proofs[0]})
	if !reflect.DeepEqual(forward, reverse) {
		t.Fatalf("DEB proof tie depends on discovery order: forward=%+v reverse=%+v", forward.deb, reverse.deb)
	}
	if !reflect.DeepEqual(forward, proofs[1]) {
		t.Fatalf("candidate spool did not retain the canonical tied proof: got=%+v want=%+v", forward.deb, proofs[1].deb)
	}
}

func storedCandidateProof(t *testing.T, candidate syncer.Candidate, order []candidateProof) candidateProof {
	t.Helper()
	store, err := newCandidateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	for _, proof := range order {
		if err := store.add(candidate, proof); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.finalize(); err != nil {
		t.Fatal(err)
	}
	record, err := store.get(candidate.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return record.Proof
}
