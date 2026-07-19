package publish

import (
	"bytes"
	"strings"
	"testing"
)

func TestLegacyPurgePlanAttestationCanonicalRoundTrip(t *testing.T) {
	attestation := LegacyPurgePlanAttestation{
		Target: TargetCloudflare, Generation: 7, TransactionID: "legacy-7",
		AnchorCommit:     strings.Repeat("1", 40),
		GenerationSHA256: strings.Repeat("2", 64),
		CheckpointSHA256: strings.Repeat("3", 64),
		PlanSHA256:       strings.Repeat("4", 64),
		ReceiptSHA256:    strings.Repeat("5", 64),
	}
	body, err := attestation.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeLegacyPurgePlanAttestation(body)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Schema != LegacyPurgePlanAttestationSchema || decoded.Target != attestation.Target || decoded.Generation != attestation.Generation {
		t.Fatalf("decoded=%#v", decoded)
	}
	bodyAgain, err := decoded.Canonical()
	if err != nil || !bytes.Equal(body, bodyAgain) {
		t.Fatalf("canonical bytes changed: err=%v", err)
	}
}

func TestLegacyPurgePlanAttestationRejectsNoncanonicalAndInvalidBindings(t *testing.T) {
	valid := LegacyPurgePlanAttestation{
		Target: TargetTencent, Generation: 1, TransactionID: "legacy-1",
		AnchorCommit:     strings.Repeat("1", 40),
		GenerationSHA256: strings.Repeat("2", 64),
		CheckpointSHA256: strings.Repeat("3", 64),
		PlanSHA256:       strings.Repeat("4", 64),
		ReceiptSHA256:    strings.Repeat("5", 64),
	}
	body, err := valid.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"trailing-newline": append(append([]byte(nil), body...), '\n'),
		"unknown-field":    append(append([]byte(nil), body[:len(body)-1]...), []byte(",\"extra\":true}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLegacyPurgePlanAttestation(candidate); err == nil {
				t.Fatal("decoder accepted noncanonical attestation")
			}
		})
	}
	for name, mutate := range map[string]func(*LegacyPurgePlanAttestation){
		"zero-generation": func(value *LegacyPurgePlanAttestation) { value.Generation = 0 },
		"bad-target":      func(value *LegacyPurgePlanAttestation) { value.Target = "other" },
		"bad-anchor":      func(value *LegacyPurgePlanAttestation) { value.AnchorCommit = "not-a-commit" },
		"bad-plan-sha":    func(value *LegacyPurgePlanAttestation) { value.PlanSHA256 = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := candidate.Canonical(); err == nil {
				t.Fatal("canonical encoder accepted invalid attestation")
			}
		})
	}
}

func TestLegacyPurgePlanAttestationValidationOrderIsDeterministic(t *testing.T) {
	invalid := LegacyPurgePlanAttestation{
		Target: TargetCloudflare, Generation: 1, TransactionID: "legacy-1",
		AnchorCommit:     strings.Repeat("1", 40),
		GenerationSHA256: "bad-generation",
		CheckpointSHA256: "bad-checkpoint",
		PlanSHA256:       "bad-plan",
		ReceiptSHA256:    "bad-receipt",
	}
	for iteration := 0; iteration < 100; iteration++ {
		_, err := invalid.Canonical()
		if err == nil || err.Error() != "invalid legacy purge plan attestation generation sha256" {
			t.Fatalf("iteration=%d err=%v", iteration, err)
		}
	}
}
