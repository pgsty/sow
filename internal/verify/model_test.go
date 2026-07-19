package verify

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestRunIsDeterministicBoundedAndRequiresLayerCoverage(t *testing.T) {
	checks := []Check{
		CheckFunc{CheckID: "z-l2", CheckLayer: LayerL2, Run: func(_ context.Context, r *Recorder) error {
			r.Add(Finding{Layer: LayerL2, Severity: SeverityWarning, Category: CategoryDrift, Code: "Z", Subject: "two", Message: "warning"})
			return nil
		}},
		CheckFunc{CheckID: "a-l1", CheckLayer: LayerL1, Run: func(_ context.Context, r *Recorder) error {
			for _, subject := range []string{"c", "a", "b"} {
				r.Add(Finding{Layer: LayerL1, Severity: SeverityError, Category: CategoryIntegrity, Code: "A", Subject: subject, Message: "failure", Fields: []Field{{Key: "z", Value: "2"}, {Key: "a", Value: "1"}}})
			}
			return nil
		}},
	}
	request := Request{Layers: []Layer{LayerL2, LayerL1}, Checks: checks, Workers: 2, MaxFindings: 2}
	first := Run(context.Background(), request)
	second := Run(context.Background(), request)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("reports are not deterministic:\n%#v\n%#v", first, second)
	}
	if first.Outcome != OutcomeFailed || first.Exit != ExitVerification {
		t.Fatalf("classification = %s/%d", first.Outcome, first.Exit)
	}
	if first.Summary.Errors != 3 || first.Summary.Warnings != 1 || first.Summary.Suppressed != 2 || len(first.Findings) != 2 {
		t.Fatalf("unexpected bounded summary: %+v findings=%d", first.Summary, len(first.Findings))
	}
	if len(first.Checks) != 2 || first.Checks[0].ID != "a-l1" || first.Checks[1].ID != "z-l2" {
		t.Fatalf("checks not canonical: %+v", first.Checks)
	}
	if got := first.Findings[0].Fields; len(got) != 2 || got[0].Key != "a" {
		t.Fatalf("fields not sorted: %+v", got)
	}

	missing := Run(context.Background(), Request{Layers: []Layer{LayerL4}})
	if missing.Outcome != OutcomeIncomplete || missing.Exit != ExitOperational || !hasCode(missing, "VERIFY_LAYER_UNCONFIGURED") {
		t.Fatalf("missing L4 probe must be incomplete: %+v", missing)
	}
}

func TestRunSeparatesOperationalFailureFromIntegrity(t *testing.T) {
	report := Run(context.Background(), Request{Layers: []Layer{LayerL3}, Checks: []Check{
		CheckFunc{CheckID: "transport", CheckLayer: LayerL3, Run: func(context.Context, *Recorder) error {
			return errors.New("secret-token-must-not-surface")
		}},
	}})
	if report.Outcome != OutcomeIncomplete || report.Exit != ExitOperational || !hasCode(report, "VERIFY_CHECK_OPERATIONAL") {
		t.Fatalf("operational result = %+v", report)
	}
	for _, finding := range report.Findings {
		if finding.Message == "secret-token-must-not-surface" {
			t.Fatal("raw operational error leaked into report")
		}
	}
}

func hasCode(report Report, code string) bool {
	for _, finding := range report.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
