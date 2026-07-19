package publish

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestTargetGenerationCompatibilityFreezesCompleteS2Identity(t *testing.T) {
	generation := validCompatibilityTargetGeneration(t)
	body, err := generation.Canonical()
	if err != nil {
		t.Fatalf("canonical compatibility generation: %v", err)
	}
	decoded, err := DecodeTargetGeneration(body)
	if err != nil {
		t.Fatalf("decode canonical compatibility generation: %v", err)
	}
	if len(decoded.Compatibility) != 1 || decoded.Compatibility[0] != generation.Compatibility[0] {
		t.Fatalf("compatibility identity changed across round trip: got=%+v want=%+v", decoded.Compatibility, generation.Compatibility)
	}

	tests := []struct {
		name   string
		mutate func(*CompatibilityState)
	}{
		{name: "freeze commit", mutate: func(value *CompatibilityState) { value.FreezeCommit = "" }},
		{name: "witness sha", mutate: func(value *CompatibilityState) { value.WitnessSHA256 = "" }},
		{name: "witness git", mutate: func(value *CompatibilityState) { value.WitnessGit = "" }},
		{name: "witness size", mutate: func(value *CompatibilityState) { value.WitnessSize = 0 }},
		{name: "candidate manifest sha", mutate: func(value *CompatibilityState) { value.CandidateManifestSHA256 = "" }},
		{name: "candidate manifest git", mutate: func(value *CompatibilityState) { value.CandidateManifestGit = "" }},
		{name: "candidate manifest size", mutate: func(value *CompatibilityState) { value.CandidateManifestSize = 0 }},
		{name: "candidate receipt sha", mutate: func(value *CompatibilityState) { value.CandidateReceiptSHA256 = "" }},
		{name: "candidate receipt git", mutate: func(value *CompatibilityState) { value.CandidateReceiptGit = "" }},
		{name: "candidate receipt size", mutate: func(value *CompatibilityState) { value.CandidateReceiptSize = 0 }},
		{name: "repomd sha", mutate: func(value *CompatibilityState) { value.RepomdSHA256 = "" }},
		{name: "repository key sha", mutate: func(value *CompatibilityState) { value.RepositoryKeySHA256 = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := generation
			changed.Compatibility = append([]CompatibilityState(nil), generation.Compatibility...)
			test.mutate(&changed.Compatibility[0])
			if _, err := changed.Canonical(); err == nil {
				t.Fatalf("generation accepted compatibility identity without %s", test.name)
			}
		})
	}
}

func TestTargetGenerationCompatibilityCutoverIdentityIsAllOrNothing(t *testing.T) {
	generation := validCompatibilityTargetGeneration(t)
	if _, err := generation.Canonical(); err != nil {
		t.Fatalf("cutover-absent frozen generation: %v", err)
	}

	partial := generation
	partial.Compatibility = append([]CompatibilityState(nil), generation.Compatibility...)
	partial.Compatibility[0].CutoverSHA256 = strings.Repeat("a", 64)
	if _, err := partial.Canonical(); err == nil {
		t.Fatal("partial cutover identity was accepted")
	}

	complete := generation
	complete.Compatibility = append([]CompatibilityState(nil), generation.Compatibility...)
	complete.Compatibility[0].CutoverSHA256 = strings.Repeat("a", 64)
	complete.Compatibility[0].CutoverGit = strings.Repeat("b", 40)
	complete.Compatibility[0].CutoverSize = 211
	if _, err := complete.Canonical(); err != nil {
		t.Fatalf("complete cutover identity was rejected: %v", err)
	}
}

func validCompatibilityTargetGeneration(t *testing.T) TargetGeneration {
	t.Helper()
	id := "infra-legacy-x86-64"
	channel := ChannelState{
		View: "latest", Repo: id, OS: "cross-el", Arch: "x86_64", Generation: 1,
		RemoteKey:  ".sow/channels/latest/" + id + "/cross-el/x86_64.json",
		LegacyRoot: "yum/infra/x86_64",
	}
	channelBody, err := channel.CanonicalBody()
	if err != nil {
		t.Fatal(err)
	}
	channelDigest := sha256.Sum256(channelBody)
	channel.BodySHA256 = hex.EncodeToString(channelDigest[:])

	compatibility := CompatibilityState{
		ID: id, Root: "yum/infra/x86_64", Carrier: "yum-infra-legacy-compat", OwnerRepo: "infra-el9",
		SourceRef: "refs/sow/compatibility/yum-source/" + id, SourceCommit: strings.Repeat("1", 40),
		FreezeRef: "refs/sow/compatibility/yum/" + id, FreezeCommit: strings.Repeat("2", 40),
		SourceRoot:           "compatibility/yum/" + id + "/source.tsv",
		SourceManifestSHA256: strings.Repeat("1", 64), SourceManifestGit: strings.Repeat("3", 40), SourceManifestSize: 101,
		AdoptionSHA256: strings.Repeat("2", 64), AdoptionGit: strings.Repeat("4", 40), AdoptionSize: 102,
		WitnessSHA256: strings.Repeat("3", 64), WitnessGit: strings.Repeat("5", 40), WitnessSize: 103,
		PayloadManifestSHA256: strings.Repeat("4", 64), PayloadManifestGit: strings.Repeat("6", 40), PayloadManifestSize: 104,
		PackageTrustSHA256: strings.Repeat("5", 64), PackageTrustGit: strings.Repeat("7", 40), PackageTrustSize: 105,
		CandidateManifestSHA256: strings.Repeat("6", 64), CandidateManifestGit: strings.Repeat("8", 40), CandidateManifestSize: 106,
		CandidateReceiptSHA256: strings.Repeat("7", 64), CandidateReceiptGit: strings.Repeat("9", 40), CandidateReceiptSize: 107,
		RepomdSHA256: strings.Repeat("8", 64), RepositoryKeySHA256: strings.Repeat("9", 64),
		RouteTarget: "compatibility", RouteRoot: "yum/infra/x86_64", ChannelRemoteKey: channel.RemoteKey,
	}
	return TargetGeneration{
		Schema: TargetGenerationSchema, Target: TargetCloudflare, Generation: 1,
		DesiredCommit: strings.Repeat("a", 40), IntentView: "latest", ConfigSHA256: strings.Repeat("b", 64),
		Refs:          []RefState{{Name: "refs/sow/views/latest/infra-el9/el9/x86_64", Commit: strings.Repeat("c", 40), ManifestSHA256: strings.Repeat("d", 64)}},
		Compatibility: []CompatibilityState{compatibility}, Channels: []ChannelState{channel}, ContentManifestSHA256: strings.Repeat("e", 64),
	}
}
