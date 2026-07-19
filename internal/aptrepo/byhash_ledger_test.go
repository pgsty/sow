package aptrepo

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestByHashLedgerAdvancesThreeGenerationsAndReplays(t *testing.T) {
	ledger, err := NewByHashLedger("views/beta", "apt-test", "jammy")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	shared := []string{testByHashPath("a"), testByHashPath("b")}
	generations := []ByHashGeneration{
		testByHashGeneration(strings.Repeat("1", 64), now, append(shared, testByHashPath("c"))),
		testByHashGeneration(strings.Repeat("2", 64), now, append(shared, testByHashPath("d"))),
		testByHashGeneration(strings.Repeat("3", 64), now, append(shared, testByHashPath("e"))),
	}
	for index, generation := range generations {
		next, plan, err := ledger.Advance(generation, 2)
		if err != nil {
			t.Fatalf("advance %d: %v", index+1, err)
		}
		ledger = next
		if index == 2 && !reflect.DeepEqual(plan.Remove, []string{testByHashPath("c")}) {
			t.Fatalf("third cleanup removes %v", plan.Remove)
		}
	}
	if ledger.LastSequence != 3 || len(ledger.Generations) != 2 || ledger.Generations[0].ID != generations[1].ID || ledger.Generations[1].ID != generations[2].ID {
		t.Fatalf("retained ledger = %+v", ledger)
	}
	encoded, err := MarshalByHashLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeByHashLedger(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	replayed, plan, err := decoded.Advance(generations[2], 2)
	if err != nil {
		t.Fatal(err)
	}
	replayedBytes, err := MarshalByHashLedger(replayed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, replayedBytes) || len(plan.Remove) != 0 {
		t.Fatalf("replay changed ledger=%t remove=%v", !bytes.Equal(encoded, replayedBytes), plan.Remove)
	}
}

func TestByHashLedgerEquivalentIndexSetsDoNotConsumeRetention(t *testing.T) {
	ledger, err := NewByHashLedger("views/beta", "apt-test", "jammy")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	shared := []string{testByHashPath("a"), testByHashPath("b")}
	first := testByHashGeneration(strings.Repeat("1", 64), now, append(shared, testByHashPath("c")))
	second := testByHashGeneration(strings.Repeat("2", 64), now.Add(time.Second), append(shared, testByHashPath("d")))
	checkpointOnly := testByHashGeneration(strings.Repeat("3", 64), now.Add(2*time.Second), append(shared, testByHashPath("d")))
	for _, generation := range []ByHashGeneration{first, second} {
		ledger, _, err = ledger.Advance(generation, 2)
		if err != nil {
			t.Fatal(err)
		}
	}
	ledger, plan, err := ledger.Advance(checkpointOnly, 2)
	if err != nil {
		t.Fatal(err)
	}
	if ledger.LastSequence != 3 || ledger.LiveGeneration != checkpointOnly.ID || len(ledger.Generations) != 2 ||
		ledger.Generations[0].ID != first.ID || ledger.Generations[1].ID != checkpointOnly.ID {
		t.Fatalf("equivalent checkpoint consumed a retention slot: %+v", ledger)
	}
	if len(plan.Remove) != 0 {
		t.Fatalf("equivalent checkpoint removed a still-retained index: %v", plan.Remove)
	}

	fourth := testByHashGeneration(strings.Repeat("4", 64), now.Add(3*time.Second), append(shared, testByHashPath("e")))
	ledger, plan, err = ledger.Advance(fourth, 2)
	if err != nil {
		t.Fatal(err)
	}
	if ledger.LastSequence != 4 || len(ledger.Generations) != 2 || ledger.Generations[0].ID != checkpointOnly.ID || ledger.Generations[1].ID != fourth.ID {
		t.Fatalf("distinct index retention did not advance: %+v", ledger)
	}
	if !reflect.DeepEqual(plan.Remove, []string{testByHashPath("c")}) {
		t.Fatalf("distinct generation cleanup removes %v", plan.Remove)
	}
}

func TestByHashLedgerDecodeFailsClosedOnDamageAndUnknownFields(t *testing.T) {
	ledger, err := NewByHashLedger("views/latest", "apt-test", "trixie")
	if err != nil {
		t.Fatal(err)
	}
	generation := testByHashGeneration(strings.Repeat("4", 64), time.Now().UTC(), []string{testByHashPath("a"), testByHashPath("b"), testByHashPath("c")})
	ledger, _, err = ledger.Advance(generation, 2)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalByHashLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(encoded, []byte(`"repo": "apt-test"`), []byte(`"repo": "evil-test"`), 1)
	if _, err := DecodeByHashLedger(bytes.NewReader(tampered)); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered ledger error = %v", err)
	}
	unknown := bytes.Replace(encoded, []byte(`"schema":`), []byte(`"unknown": true, "schema":`), 1)
	if _, err := DecodeByHashLedger(bytes.NewReader(unknown)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown-field ledger error = %v", err)
	}
}
