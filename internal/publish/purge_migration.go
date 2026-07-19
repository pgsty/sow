package publish

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const LegacyPurgePlanAttestationSchema = "sow-legacy-purge-plan-attestation/v1"

// LegacyPurgePlanAttestation is an explicit local migration witness for a v1
// checkpoint whose nonempty purge plan predated Checkpoint.PlanSHA256. It does
// not rewrite the historical checkpoint. Instead, it binds that checkpoint,
// its plan, and the atomic provider receipt to the immutable Git publication
// anchor from which an operator performed a fail-closed repair.
//
// The document intentionally has no wall-clock or operator-controlled comment
// fields: the same valid historical envelope always produces the same bytes.
type LegacyPurgePlanAttestation struct {
	Schema           string     `json:"schema"`
	Target           TargetName `json:"target"`
	Generation       uint64     `json:"generation"`
	TransactionID    string     `json:"transaction_id"`
	AnchorCommit     string     `json:"anchor_commit"`
	GenerationSHA256 string     `json:"generation_sha256"`
	CheckpointSHA256 string     `json:"checkpoint_sha256"`
	PlanSHA256       string     `json:"plan_sha256"`
	ReceiptSHA256    string     `json:"receipt_sha256"`
}

func (a LegacyPurgePlanAttestation) normalized() (LegacyPurgePlanAttestation, error) {
	if a.Schema == "" {
		a.Schema = LegacyPurgePlanAttestationSchema
	}
	if a.Schema != LegacyPurgePlanAttestationSchema {
		return a, fmt.Errorf("legacy purge plan attestation schema %q is not %q", a.Schema, LegacyPurgePlanAttestationSchema)
	}
	if err := a.Target.Validate(); err != nil {
		return a, err
	}
	if a.Generation == 0 || !transactionIDPat.MatchString(a.TransactionID) || !gitHashPattern.MatchString(a.AnchorCommit) {
		return a, errors.New("invalid legacy purge plan attestation identity")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "generation", value: a.GenerationSHA256},
		{name: "checkpoint", value: a.CheckpointSHA256},
		{name: "plan", value: a.PlanSHA256},
		{name: "receipt", value: a.ReceiptSHA256},
	} {
		if !hexSHA256Pattern.MatchString(field.value) {
			return a, fmt.Errorf("invalid legacy purge plan attestation %s sha256", field.name)
		}
	}
	return a, nil
}

func (a LegacyPurgePlanAttestation) Canonical() ([]byte, error) {
	normalized, err := a.normalized()
	if err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

// DecodeLegacyPurgePlanAttestation accepts exactly the canonical JSON form.
// Unknown fields, trailing data, and alternate encodings are rejected so the
// canonical Git blob identity is itself stable evidence.
func DecodeLegacyPurgePlanAttestation(data []byte) (LegacyPurgePlanAttestation, error) {
	var attestation LegacyPurgePlanAttestation
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&attestation); err != nil {
		return attestation, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return attestation, errors.New("legacy purge plan attestation has trailing JSON")
		}
		return attestation, err
	}
	canonical, err := attestation.Canonical()
	if err != nil {
		return attestation, err
	}
	if !bytes.Equal(data, canonical) {
		return attestation, errors.New("legacy purge plan attestation is not canonical JSON")
	}
	return attestation, nil
}
