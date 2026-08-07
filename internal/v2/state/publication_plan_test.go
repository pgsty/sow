package state

import (
	"reflect"
	"strings"
	"testing"
)

func TestBuildPublicationPlanUsesIndependentProtocolPointerOrder(t *testing.T) {
	manifest := []GenerationFile{
		{Path: "dists/el9/x86_64/repodata/primary.xml.gz", Phase: "metadata", Size: 1, SHA256: strings.Repeat("1", 64)},
		{Path: "dists/el9/x86_64/repodata/repomd.xml", Phase: "pointer", Size: 2, SHA256: strings.Repeat("2", 64)},
		{Path: "dists/el9/x86_64/repodata/repomd.xml.asc", Phase: "pointer", Size: 3, SHA256: strings.Repeat("3", 64)},
		{Path: "dists/noble/InRelease", Phase: "pointer", Size: 4, SHA256: strings.Repeat("4", 64)},
		{Path: "dists/noble/Release", Phase: "pointer", Size: 5, SHA256: strings.Repeat("5", 64)},
		{Path: "dists/noble/Release.gpg", Phase: "pointer", Size: 6, SHA256: strings.Repeat("6", 64)},
		{Path: "dists/noble/main/binary-amd64/Packages", Phase: "metadata", Size: 9, SHA256: strings.Repeat("9", 64)},
		{Path: "dists/noble/main/binary-amd64/by-hash/SHA256/abc", Phase: "metadata", Size: 7, SHA256: strings.Repeat("7", 64)},
		{Path: "pool/p/pkg/pkg.deb", Phase: "payload", Size: 8, SHA256: strings.Repeat("8", 64)},
	}
	input := PublicationPlanInput{
		RepositoryID: "12345678-1234-4123-8123-123456789abc", TargetIdentity: strings.Repeat("a", 64), TargetGeneration: 1,
		TargetManifest: manifest, Changes: DiffManifests(nil, manifest),
	}
	plan, err := BuildPublicationPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.CommitUnits) != 2 || plan.CommitUnits[0].Protocol != "rpm" || plan.CommitUnits[1].Protocol != "apt" {
		t.Fatalf("commit units=%#v", plan.CommitUnits)
	}
	paths := func(ops []PublicationPlanOperation) []string {
		out := make([]string, len(ops))
		for index := range ops {
			out[index] = ops[index].Path
		}
		return out
	}
	if got, want := paths(plan.CommitUnits[0].Pointers), []string{"dists/el9/x86_64/repodata/repomd.xml.asc", "dists/el9/x86_64/repodata/repomd.xml"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("RPM pointer order=%v want=%v", got, want)
	}
	if got, want := paths(plan.CommitUnits[1].Pointers), []string{"dists/noble/Release.gpg", "dists/noble/Release", "dists/noble/InRelease"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("APT pointer order=%v want=%v", got, want)
	}
	if len(plan.Payload) != 1 || len(plan.ImmutableMetadata) != 2 || len(plan.StableAliases) != 1 || !validSHA256Text(plan.PlanSHA256) {
		t.Fatalf("plan=%#v", plan)
	}
	bytes, err := PublicationPlanBytes(plan)
	if err != nil || len(bytes) == 0 {
		t.Fatalf("canonical plan bytes: len=%d err=%v", len(bytes), err)
	}
	again, err := BuildPublicationPlan(input)
	if err != nil || again.PlanSHA256 != plan.PlanSHA256 {
		t.Fatalf("non-deterministic digest: %s %s err=%v", plan.PlanSHA256, again.PlanSHA256, err)
	}

	// Fault at every pointer boundary: immutable prerequisites are already a
	// complete prefix, and recovery can only observe an exact pointer prefix.
	for _, unit := range plan.CommitUnits {
		for stop := 0; stop <= len(unit.Pointers); stop++ {
			applied := append([]PublicationPlanOperation(nil), unit.Pointers[:stop]...)
			if len(applied) != stop || stop > 0 && !reflect.DeepEqual(applied, unit.Pointers[:stop]) || len(plan.Payload)+len(plan.ImmutableMetadata)+len(plan.StableAliases) != 4 {
				t.Fatalf("fault prefix %s/%d is not recoverable", unit.ViewID, stop)
			}
		}
	}
}

func TestBuildPublicationPlanRejectsNonCanonicalAndIncompleteInputs(t *testing.T) {
	base := []GenerationFile{{Path: "dists/noble/Release", Phase: "pointer", Size: 1, SHA256: strings.Repeat("1", 64)}}
	valid := PublicationPlanInput{RepositoryID: "12345678-1234-4123-8123-123456789abc", TargetIdentity: strings.Repeat("a", 64), BaseCheckpoint: strings.Repeat("b", 64), TargetGeneration: 2, BaseManifest: base, TargetManifest: []GenerationFile{{Path: "dists/noble/Release", Phase: "pointer", Size: 2, SHA256: strings.Repeat("2", 64)}}}
	valid.Changes = DiffManifests(valid.BaseManifest, valid.TargetManifest)
	if _, err := BuildPublicationPlan(valid); err != nil {
		t.Fatal(err)
	}
	updated, err := BuildPublicationPlan(valid)
	if err != nil || updated.CommitUnits[0].Pointers[0].ExpectedOldSHA256 != strings.Repeat("1", 64) {
		t.Fatalf("stable pointer CAS identity missing: plan=%#v err=%v", updated, err)
	}

	duplicate := valid
	duplicate.TargetManifest = append(append([]GenerationFile(nil), valid.TargetManifest...), valid.TargetManifest[0])
	duplicate.Changes = DiffManifests(duplicate.BaseManifest, duplicate.TargetManifest)
	if _, err := BuildPublicationPlan(duplicate); err == nil {
		t.Fatal("duplicate manifest path accepted")
	}

	unsorted := valid
	unsorted.Changes = []FileChange{{Operation: "delete", Path: "z", Phase: "delete"}, valid.Changes[0]}
	if _, err := BuildPublicationPlan(unsorted); err == nil {
		t.Fatal("non-canonical Changeset accepted")
	}

	incompleteManifest := []GenerationFile{
		{Path: "dists/noble/InRelease", Phase: "pointer", Size: 1, SHA256: strings.Repeat("1", 64)},
		{Path: "dists/noble/Release", Phase: "pointer", Size: 2, SHA256: strings.Repeat("2", 64)},
	}
	incomplete := PublicationPlanInput{RepositoryID: valid.RepositoryID, TargetIdentity: valid.TargetIdentity, TargetGeneration: 1, TargetManifest: incompleteManifest, Changes: DiffManifests(nil, incompleteManifest)}
	if _, err := BuildPublicationPlan(incomplete); err == nil {
		t.Fatal("signed APT unit without Release.gpg accepted")
	}

	invalidPhase := valid
	invalidPhase.TargetManifest = []GenerationFile{{Path: "pool/p/pkg/pkg.rpm", Phase: "metadata", Size: 1, SHA256: strings.Repeat("1", 64)}}
	invalidPhase.Changes = DiffManifests(invalidPhase.BaseManifest, invalidPhase.TargetManifest)
	if _, err := BuildPublicationPlan(invalidPhase); err == nil {
		t.Fatal("manifest with phase inconsistent with single-payload layout accepted")
	}

	signedBase := []GenerationFile{
		{Path: "dists/noble/InRelease", Phase: "pointer", Size: 1, SHA256: strings.Repeat("1", 64)},
		{Path: "dists/noble/Release", Phase: "pointer", Size: 1, SHA256: strings.Repeat("2", 64)},
		{Path: "dists/noble/Release.gpg", Phase: "pointer", Size: 1, SHA256: strings.Repeat("3", 64)},
	}
	unsignedTarget := []GenerationFile{{Path: "dists/noble/Release", Phase: "pointer", Size: 0, SHA256: strings.Repeat("4", 64)}}
	modeChange := PublicationPlanInput{RepositoryID: valid.RepositoryID, TargetIdentity: valid.TargetIdentity, BaseCheckpoint: valid.BaseCheckpoint, TargetGeneration: 3, BaseManifest: signedBase, TargetManifest: unsignedTarget, Changes: DiffManifests(signedBase, unsignedTarget)}
	if _, err := BuildPublicationPlan(modeChange); err == nil || !strings.Contains(err.Error(), "pointer removal") {
		t.Fatalf("signed-to-unsigned transition error=%v", err)
	}
	zeroPlan, err := BuildPublicationPlan(PublicationPlanInput{RepositoryID: valid.RepositoryID, TargetIdentity: valid.TargetIdentity, TargetGeneration: 1, TargetManifest: unsignedTarget, Changes: DiffManifests(nil, unsignedTarget)})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := PublicationPlanBytes(zeroPlan)
	if err != nil || !strings.Contains(string(wire), `"size":0`) {
		t.Fatalf("zero-size add/update was lost: %s err=%v", wire, err)
	}
}

func TestBuildPublicationPlanDeletionCandidateCarriesExactBaseEvidence(t *testing.T) {
	base := []GenerationFile{{Path: "pool/p/pkg/old.rpm", Phase: "payload", Size: 42, SHA256: strings.Repeat("d", 64)}}
	input := PublicationPlanInput{RepositoryID: "12345678-1234-4123-8123-123456789abc", TargetIdentity: strings.Repeat("a", 64), BaseCheckpoint: strings.Repeat("b", 64), TargetGeneration: 2, BaseManifest: base, TargetManifest: []GenerationFile{}, Changes: DiffManifests(base, nil)}
	plan, err := BuildPublicationPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.DeleteCandidates) != 1 || plan.DeleteCandidates[0].Size != 42 || plan.DeleteCandidates[0].SHA256 != strings.Repeat("d", 64) || plan.DeleteCandidates[0].ExpectedOldSHA256 != strings.Repeat("d", 64) {
		t.Fatalf("deletion evidence=%#v", plan.DeleteCandidates)
	}
}
