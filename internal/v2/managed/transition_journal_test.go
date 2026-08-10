package managed

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/v2/state"
)

const transitionTestRepositoryID = "12345678-1234-4123-8123-123456789abc"

func testTransitionJournal(size int64) C2ToSingleTransition {
	return C2ToSingleTransition{
		Schema:               transitionSchema,
		RepositoryID:         transitionTestRepositoryID,
		FromLayout:           state.LayoutC2V1,
		ToLayout:             state.LayoutSinglePayloadV1,
		BaseGeneration:       42,
		BaseManifestSHA256:   strings.Repeat("1", 64),
		TargetManifestSHA256: strings.Repeat("2", 64),
		Phase:                "planned",
		Pointers: []TransitionPointer{
			{ViewID: "dists/el9/x86_64", Kind: "signature_companion", Path: "dists/el9/x86_64/repodata/repomd.xml.asc", OldSHA256: strings.Repeat("3", 64), NewSHA256: strings.Repeat("4", 64), State: "old"},
			{ViewID: "dists/el9/x86_64", Kind: "commit_pointer", Path: "dists/el9/x86_64/repodata/repomd.xml", OldSHA256: strings.Repeat("5", 64), NewSHA256: strings.Repeat("6", 64), State: "old"},
		},
		LegacyAliases: []TransitionLegacyAlias{{Path: "dists/el9/x86_64/pool/p/pkg/pkg.rpm", Size: TransitionSize(size), SHA256: strings.Repeat("a", 64), State: "present"}},
	}
}

func TestTransitionJournalExactCanonicalWire(t *testing.T) {
	journal := testTransitionJournal(0)
	canonical, err := canonicalTransitionJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"base_generation":"00000000000000000042","base_manifest_sha256":"` + strings.Repeat("1", 64) +
		`","commit_intent":false,"from_layout":"c2-v1","grace_not_before":null,"legacy_aliases":[{"path":"dists/el9/x86_64/pool/p/pkg/pkg.rpm","receipt_sha256":null,"sha256":"` + strings.Repeat("a", 64) +
		`","size":"0","state":"present"}],"phase":"planned","pointers":[{"kind":"signature_companion","new_sha256":"` + strings.Repeat("4", 64) +
		`","old_sha256":"` + strings.Repeat("3", 64) + `","path":"dists/el9/x86_64/repodata/repomd.xml.asc","state":"old","view_id":"dists/el9/x86_64"},{"kind":"commit_pointer","new_sha256":"` + strings.Repeat("6", 64) +
		`","old_sha256":"` + strings.Repeat("5", 64) + `","path":"dists/el9/x86_64/repodata/repomd.xml","state":"old","view_id":"dists/el9/x86_64"}],"repository_id":"12345678-1234-4123-8123-123456789abc","schema":"sow/transition/c2-to-single/v1","target_manifest_sha256":"` + strings.Repeat("2", 64) + `","to_layout":"single-payload-v1"}`
	if string(canonical) != want {
		t.Fatalf("journal wire:\n%s\nwant:\n%s", canonical, want)
	}
	parsed, identity, err := ParseC2ToSingleTransition(canonical)
	if err != nil || !bytes.Equal(canonical, []byte(want)) || parsed.BaseGeneration != 42 || !lowercaseSHA256.MatchString(identity) {
		t.Fatalf("parsed=%#v identity=%q err=%v", parsed, identity, err)
	}
}

func TestTransitionAliasSizeAndDeletionReceiptGoldenVectors(t *testing.T) {
	tests := []struct {
		size    int64
		receipt string
	}{
		{0, "fa803f28f5db52eeda607696fb852db8ed322aef58e989e0451ca15d638593f4"},
		{1, "bc482dcfe8e242781aa54d0a449b75d6aa5c72640f57c8b97aff2bff58c820c4"},
		{9007199254740992, "f1a03efb4934f3e838d558ccf557908f17a1d40805d112180d47fd096eff87a3"},
		{math.MaxInt64, "8b74f522e0d10feec767500f6993657a6fb89a1c99dd335d2b1f652a79b5fcdd"},
	}
	for _, test := range tests {
		t.Run(strings.ReplaceAll(jsonNumber(test.size), "-", "negative"), func(t *testing.T) {
			receipt, err := CanonicalAliasDeletionReceipt(transitionTestRepositoryID, "dists/el9/x86_64/pool/p/pkg/pkg.rpm", test.size, strings.Repeat("a", 64))
			if err != nil || receipt != test.receipt {
				t.Fatalf("receipt=%q want=%q err=%v", receipt, test.receipt, err)
			}
			journal := testTransitionJournal(test.size)
			wire, err := canonicalTransitionJournal(journal)
			if err != nil || !bytes.Contains(wire, []byte(`"size":"`+jsonNumber(test.size)+`"`)) {
				t.Fatalf("wire=%s err=%v", wire, err)
			}
			if _, _, err := ParseC2ToSingleTransition(wire); err != nil {
				t.Fatal(err)
			}
			journal.Phase, journal.CommitIntent = "done", true
			deadline := "2026-08-05T12:34:56Z"
			journal.GraceNotBefore = &deadline
			for index := range journal.Pointers {
				journal.Pointers[index].State = "new"
			}
			journal.LegacyAliases[0].State = "deleted"
			journal.LegacyAliases[0].ReceiptSHA256 = &receipt
			wire, err = canonicalTransitionJournal(journal)
			if err != nil {
				t.Fatal(err)
			}
			if parsed, _, err := ParseC2ToSingleTransition(wire); err != nil || parsed.LegacyAliases[0].ReceiptSHA256 == nil || *parsed.LegacyAliases[0].ReceiptSHA256 != test.receipt {
				t.Fatalf("parsed=%#v err=%v", parsed, err)
			}
		})
	}
}

func TestTransitionJournalRejectsRecursiveUnknownDuplicateAndNonCanonicalJSON(t *testing.T) {
	canonical, err := canonicalTransitionJournal(testTransitionJournal(1))
	if err != nil {
		t.Fatal(err)
	}
	structOrder, err := json.Marshal(testTransitionJournal(1))
	if err != nil {
		t.Fatal(err)
	}
	invalid := map[string][]byte{
		"top-duplicate":      bytes.Replace(canonical, []byte(`"phase":`), []byte(`"phase":"planned","phase":`), 1),
		"nested-duplicate":   bytes.Replace(canonical, []byte(`"path":"dists/el9/x86_64/pool`), []byte(`"path":"dists/el9/x86_64/pool/p/pkg/pkg.rpm","path":"dists/el9/x86_64/pool`), 1),
		"top-unknown":        append(append([]byte(nil), canonical[:len(canonical)-1]...), []byte(`,"unknown":null}`)...),
		"nested-unknown":     bytes.Replace(canonical, []byte(`"state":"present"`), []byte(`"state":"present","unknown":null`), 1),
		"numeric-generation": bytes.Replace(canonical, []byte(`"base_generation":"00000000000000000042"`), []byte(`"base_generation":42`), 1),
		"numeric-size":       bytes.Replace(canonical, []byte(`"size":"1"`), []byte(`"size":1`), 1),
		"trailing":           append(append([]byte(nil), canonical...), '\n'),
		"struct-field-order": structOrder,
	}
	for name, wire := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseC2ToSingleTransition(wire); err == nil {
				t.Fatalf("accepted invalid transition journal %s", wire)
			}
		})
	}

	journal := testTransitionJournal(1)
	journal.Pointers[0], journal.Pointers[1] = journal.Pointers[1], journal.Pointers[0]
	if _, err := canonicalTransitionJournal(journal); err == nil {
		t.Fatal("accepted non-canonical pointer order")
	}
	journal = testTransitionJournal(1)
	journal.LegacyAliases = append(journal.LegacyAliases, journal.LegacyAliases[0])
	if _, err := canonicalTransitionJournal(journal); err == nil {
		t.Fatal("accepted duplicate alias")
	}
	journal = testTransitionJournal(1)
	journal.Phase = "commit_intent"
	if _, err := canonicalTransitionJournal(journal); err == nil {
		t.Fatal("accepted commit_intent phase with false commit flag")
	}
	journal = testTransitionJournal(1)
	deadline := "2026-08-05T12:34:56.123Z"
	journal.GraceNotBefore = &deadline
	if _, err := canonicalTransitionJournal(journal); err == nil {
		t.Fatal("accepted grace deadline before grace phase")
	}
	journal = testTransitionJournal(1)
	journal.Pointers = append(journal.Pointers, journal.Pointers[1])
	if _, err := canonicalTransitionJournal(journal); err == nil {
		t.Fatal("accepted duplicate commit pointer for one view")
	}
	journal = testTransitionJournal(1)
	journal.Pointers[0].NewSHA256 = journal.Pointers[0].OldSHA256
	if _, err := canonicalTransitionJournal(journal); err == nil {
		t.Fatal("accepted transition pointer with identical old and new digests")
	}
}

func TestCanonicalJSONStringDoesNotApplyHTMLEscapingAndTransitionPathsAreStrictASCII(t *testing.T) {
	if got := canonicalJSONString("<tag>&value>"); got != `"<tag>&value>"` {
		t.Fatalf("canonical JSON string=%s", got)
	}
	for name, mutate := range map[string]func(*C2ToSingleTransition){
		"html-special": func(journal *C2ToSingleTransition) {
			journal.LegacyAliases[0].Path = "dists/el9/x86_64/pool/p/pkg/<pkg>.rpm"
		},
		"unicode": func(journal *C2ToSingleTransition) {
			journal.Pointers[0].ViewID = "dists/el9/架构"
			journal.Pointers[0].Path = "dists/el9/架构/repodata/repomd.xml.asc"
		},
	} {
		t.Run(name, func(t *testing.T) {
			journal := testTransitionJournal(1)
			mutate(&journal)
			if _, err := canonicalTransitionJournal(journal); err == nil {
				t.Fatal("accepted a transition string outside the frozen ASCII domain")
			}
		})
	}
}

func jsonNumber(value int64) string {
	return strconv.FormatInt(value, 10)
}
