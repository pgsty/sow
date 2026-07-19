package cli

import (
	"testing"

	pub "github.com/pgsty/sow/internal/publish"
)

func TestHistoricalProbeLivenessDoesNotReachBehindDeletion(t *testing.T) {
	const rawURL = "https://repo.example.invalid/pkg/retired.tgz"
	liveness := make(map[string]bool)
	newerDelete := pub.Plan{VerifyAbsent: []pub.VerifyAbsentObject{{URL: rawURL}}}
	olderPositive := pub.Plan{Verify: []pub.VerifyObject{{URL: rawURL, Size: 7, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}
	if candidates := historicalLiveProbeCandidates(newerDelete, liveness); len(candidates) != 0 || liveness[rawURL] {
		t.Fatalf("newer deletion did not create a tombstone: candidates=%+v liveness=%v", candidates, liveness)
	}
	if candidates := historicalLiveProbeCandidates(olderPositive, liveness); len(candidates) != 0 || liveness[rawURL] {
		t.Fatalf("older positive reached behind newer deletion: candidates=%+v liveness=%v", candidates, liveness)
	}
}

func TestHistoricalProbeLivenessAllowsNewerExplicitReintroduction(t *testing.T) {
	const rawURL = "https://repo.example.invalid/pkg/reintroduced.tgz"
	newestPositive := pub.Plan{Verify: []pub.VerifyObject{{URL: rawURL, Size: 9, SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}
	middleDelete := pub.Plan{VerifyAbsent: []pub.VerifyAbsentObject{{URL: rawURL}}}
	oldestPositive := pub.Plan{Verify: []pub.VerifyObject{{URL: rawURL, Size: 7, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}
	liveness := make(map[string]bool)
	candidates := historicalLiveProbeCandidates(newestPositive, liveness)
	if len(candidates) != 1 || candidates[0].Size != 9 || !liveness[rawURL] {
		t.Fatalf("newest reintroduction was not live: candidates=%+v liveness=%v", candidates, liveness)
	}
	_ = historicalLiveProbeCandidates(middleDelete, liveness)
	candidates = historicalLiveProbeCandidates(oldestPositive, liveness)
	if len(candidates) != 1 || candidates[0].Size != 7 || !liveness[rawURL] {
		t.Fatalf("older history overrode newest liveness decision: candidates=%+v liveness=%v", candidates, liveness)
	}
}

func TestHistoricalProbeLivenessHonorsCurrentPlanTombstone(t *testing.T) {
	const rawURL = "https://repo.example.invalid/pkg/currently-deleted.tgz"
	liveness := map[string]bool{rawURL: false}
	olderPositive := pub.Plan{Probes: []pub.VerifyObject{{URL: rawURL, Size: 3, SHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}}
	if candidates := historicalLiveProbeCandidates(olderPositive, liveness); len(candidates) != 0 {
		t.Fatalf("current transaction tombstone admitted an older probe: %+v", candidates)
	}
}
