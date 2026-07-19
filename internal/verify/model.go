// Package verify composes SOW's repository engines into deterministic L1-L4
// verification reports. It never mutates canonical state or repository data.
package verify

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// Layer identifies the PRD verification boundary.
type Layer string

const (
	LayerL1 Layer = "L1"
	LayerL2 Layer = "L2"
	LayerL3 Layer = "L3"
	LayerL4 Layer = "L4"
)

// Severity is ordered from informational evidence to a release-blocking flaw.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// Category distinguishes a failed invariant from an inability to execute it.
type Category string

const (
	CategoryIntegrity       Category = "integrity"
	CategoryDrift           Category = "drift"
	CategoryConfidentiality Category = "confidentiality"
	CategoryCoverage        Category = "coverage"
	CategoryOperational     Category = "operational"
	CategoryEvidence        Category = "evidence"
)

// Field is one non-secret structured fact attached to a finding. Recorders
// sort fields by key and value before exposing a report.
type Field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Finding is stable machine output. Code and Subject are intended for filters;
// Message is human-readable and must never contain credentials.
type Finding struct {
	Layer    Layer    `json:"layer"`
	Severity Severity `json:"severity"`
	Category Category `json:"category"`
	Code     string   `json:"code"`
	Subject  string   `json:"subject,omitempty"`
	Message  string   `json:"message"`
	Fields   []Field  `json:"fields,omitempty"`
}

// Outcome is the deterministic aggregate classification.
type Outcome string

const (
	OutcomePassed     Outcome = "passed"
	OutcomeWarning    Outcome = "warning"
	OutcomeFailed     Outcome = "failed"
	OutcomeIncomplete Outcome = "incomplete"
)

// ExitClass is deliberately compatible with the CLI's public exit contract.
// An incomplete check is an internal/operational failure; a warning or failed
// invariant is verification exit 4.
type ExitClass int

const (
	ExitSuccess      ExitClass = 0
	ExitOperational  ExitClass = 1
	ExitVerification ExitClass = 4
)

// Summary counts all findings, including those suppressed by MaxFindings.
type Summary struct {
	Info        int64 `json:"info"`
	Warnings    int64 `json:"warnings"`
	Errors      int64 `json:"errors"`
	Critical    int64 `json:"critical"`
	Operational int64 `json:"operational"`
	Suppressed  int64 `json:"suppressed"`
}

// CheckResult describes one executed check without timestamps or durations,
// keeping serialized reports reproducible for the same evidence.
type CheckResult struct {
	ID       string `json:"id"`
	Layer    Layer  `json:"layer"`
	Findings int64  `json:"findings"`
	Status   string `json:"status"`
}

// Report is sorted and deterministic.
type Report struct {
	Outcome  Outcome       `json:"outcome"`
	Exit     ExitClass     `json:"exit_class"`
	Summary  Summary       `json:"summary"`
	Checks   []CheckResult `json:"checks"`
	Findings []Finding     `json:"findings"`
}

// Check is one bounded verifier. Implementations add invariant findings to the
// recorder and reserve returned errors for an inability to execute the check.
type Check interface {
	ID() string
	Layer() Layer
	Verify(context.Context, *Recorder) error
}

// CheckFunc adapts package integrations such as real apt/dnf client harnesses.
type CheckFunc struct {
	CheckID    string
	CheckLayer Layer
	Run        func(context.Context, *Recorder) error
}

func (c CheckFunc) ID() string   { return c.CheckID }
func (c CheckFunc) Layer() Layer { return c.CheckLayer }

func (c CheckFunc) Verify(ctx context.Context, recorder *Recorder) error {
	if c.Run == nil {
		return errors.New("nil verification function")
	}
	return c.Run(ctx, recorder)
}

// Request explicitly names the layers under test. Every selected layer must
// have at least one check; this prevents L3/L4 from passing merely because no
// external probe was wired.
type Request struct {
	Layers      []Layer
	Checks      []Check
	Workers     int
	MaxFindings int
}

// Recorder is safe for concurrent use and caps retained details while keeping
// exact aggregate counts.
type Recorder struct {
	mu       sync.Mutex
	max      int
	findings []Finding
	summary  Summary
	total    int64
}

func newRecorder(max int) *Recorder {
	if max <= 0 {
		max = 1000
	}
	return &Recorder{max: max}
}

// Add records one sanitized structured finding.
func (r *Recorder) Add(f Finding) {
	f.Code = strings.TrimSpace(f.Code)
	f.Subject = strings.TrimSpace(f.Subject)
	f.Message = strings.TrimSpace(f.Message)
	if !validLayer(f.Layer) {
		f.Layer = LayerL1
	}
	if !validSeverity(f.Severity) {
		f.Severity = SeverityCritical
	}
	if !validCategory(f.Category) {
		f.Category = CategoryOperational
	}
	if f.Code == "" {
		f.Code = "VERIFY_UNCLASSIFIED"
	}
	if f.Message == "" {
		f.Message = "verification finding"
	}
	sort.Slice(f.Fields, func(i, j int) bool {
		if f.Fields[i].Key != f.Fields[j].Key {
			return f.Fields[i].Key < f.Fields[j].Key
		}
		return f.Fields[i].Value < f.Fields[j].Value
	})

	r.mu.Lock()
	defer r.mu.Unlock()
	r.total++
	switch f.Severity {
	case SeverityInfo:
		r.summary.Info++
	case SeverityWarning:
		r.summary.Warnings++
	case SeverityError:
		r.summary.Errors++
	case SeverityCritical:
		r.summary.Critical++
	}
	if f.Category == CategoryOperational || f.Category == CategoryCoverage {
		r.summary.Operational++
	}
	if len(r.findings) < r.max {
		r.findings = append(r.findings, f)
	} else {
		r.summary.Suppressed++
	}
}

func (r *Recorder) snapshot() ([]Finding, Summary, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Finding(nil), r.findings...), r.summary, r.total
}

func (r *Recorder) merge(findings []Finding, summary Summary, total int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.total += total
	r.summary.Info += summary.Info
	r.summary.Warnings += summary.Warnings
	r.summary.Errors += summary.Errors
	r.summary.Critical += summary.Critical
	r.summary.Operational += summary.Operational
	r.summary.Suppressed += summary.Suppressed
	available := r.max - len(r.findings)
	if available < 0 {
		available = 0
	}
	if len(findings) > available {
		r.summary.Suppressed += int64(len(findings) - available)
		findings = findings[:available]
	}
	r.findings = append(r.findings, findings...)
}

type checkExecution struct {
	index    int
	result   CheckResult
	findings []Finding
	summary  Summary
	err      error
}

// Run executes checks with bounded parallelism, then sorts all observable
// output. Verification findings never short-circuit another independent check.
func Run(ctx context.Context, request Request) Report {
	if ctx == nil {
		ctx = context.Background()
	}
	master := newRecorder(request.MaxFindings)
	layers, layerErr := normalizeLayers(request.Layers)
	if layerErr != nil {
		master.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryCoverage, Code: "VERIFY_INVALID_LAYER_SELECTION", Message: layerErr.Error()})
		return finishReport(master, nil)
	}
	selected := make(map[Layer]bool, len(layers))
	for _, layer := range layers {
		selected[layer] = true
	}

	checks := append([]Check(nil), request.Checks...)
	sort.SliceStable(checks, func(i, j int) bool {
		if checks[i] == nil {
			return false
		}
		if checks[j] == nil {
			return true
		}
		if checks[i].Layer() != checks[j].Layer() {
			return layerRank(checks[i].Layer()) < layerRank(checks[j].Layer())
		}
		return checks[i].ID() < checks[j].ID()
	})
	seenIDs := make(map[string]struct{}, len(checks))
	coverage := make(map[Layer]int, len(layers))
	valid := make([]Check, 0, len(checks))
	for _, check := range checks {
		if check == nil {
			master.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryCoverage, Code: "VERIFY_NIL_CHECK", Message: "verification request contains a nil check"})
			continue
		}
		id := strings.TrimSpace(check.ID())
		layer := check.Layer()
		if id == "" || !validCheckID(id) || !validLayer(layer) {
			master.Add(Finding{Layer: fallbackLayer(layer), Severity: SeverityCritical, Category: CategoryCoverage, Code: "VERIFY_INVALID_CHECK", Subject: id, Message: "check ID or layer is invalid"})
			continue
		}
		if !selected[layer] {
			master.Add(Finding{Layer: layer, Severity: SeverityCritical, Category: CategoryCoverage, Code: "VERIFY_UNSELECTED_CHECK", Subject: id, Message: "check was supplied for a layer not selected by the request"})
			continue
		}
		if _, duplicate := seenIDs[id]; duplicate {
			master.Add(Finding{Layer: layer, Severity: SeverityCritical, Category: CategoryCoverage, Code: "VERIFY_DUPLICATE_CHECK", Subject: id, Message: "check IDs must be unique"})
			continue
		}
		seenIDs[id] = struct{}{}
		coverage[layer]++
		valid = append(valid, check)
	}
	for _, layer := range layers {
		if coverage[layer] == 0 {
			master.Add(Finding{Layer: layer, Severity: SeverityCritical, Category: CategoryCoverage, Code: "VERIFY_LAYER_UNCONFIGURED", Subject: string(layer), Message: "selected verification layer has no executable check"})
		}
	}

	workers := request.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > 64 {
		workers = 64
	}
	if workers > len(valid) {
		workers = len(valid)
	}
	if workers < 1 {
		return finishReport(master, nil)
	}

	jobs := make(chan int)
	results := make(chan checkExecution, len(valid))
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for index := range jobs {
				check := valid[index]
				local := newRecorder(request.MaxFindings)
				err := executeCheck(ctx, check, local)
				findings, summary, total := local.snapshot()
				status := "passed"
				if total != 0 {
					status = "findings"
				}
				if err != nil {
					status = "operational"
				}
				results <- checkExecution{index: index, result: CheckResult{ID: check.ID(), Layer: check.Layer(), Findings: total, Status: status}, findings: findings, summary: summary, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range valid {
			jobs <- index
		}
	}()
	go func() {
		group.Wait()
		close(results)
	}()

	executions := make([]checkExecution, len(valid))
	for execution := range results {
		executions[execution.index] = execution
	}
	checkResults := make([]CheckResult, 0, len(executions))
	for _, execution := range executions {
		master.merge(execution.findings, execution.summary, execution.result.Findings)
		if execution.err != nil {
			message := "check could not be completed"
			if errors.Is(execution.err, context.Canceled) || errors.Is(execution.err, context.DeadlineExceeded) {
				message = execution.err.Error()
			}
			master.Add(Finding{Layer: execution.result.Layer, Severity: SeverityCritical, Category: CategoryOperational, Code: "VERIFY_CHECK_OPERATIONAL", Subject: execution.result.ID, Message: message})
			execution.result.Findings++
		}
		checkResults = append(checkResults, execution.result)
	}
	return finishReport(master, checkResults)
}

func executeCheck(ctx context.Context, check Check, recorder *Recorder) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("verification check panicked")
		}
	}()
	return check.Verify(ctx, recorder)
}

func finishReport(recorder *Recorder, checks []CheckResult) Report {
	findings, summary, _ := recorder.snapshot()
	sort.Slice(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.Layer != right.Layer {
			return layerRank(left.Layer) < layerRank(right.Layer)
		}
		if left.Severity != right.Severity {
			return severityRank(left.Severity) > severityRank(right.Severity)
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		if left.Subject != right.Subject {
			return left.Subject < right.Subject
		}
		if left.Message != right.Message {
			return left.Message < right.Message
		}
		return findingFieldsKey(left.Fields) < findingFieldsKey(right.Fields)
	})
	sort.Slice(checks, func(i, j int) bool {
		if checks[i].Layer != checks[j].Layer {
			return layerRank(checks[i].Layer) < layerRank(checks[j].Layer)
		}
		return checks[i].ID < checks[j].ID
	})
	report := Report{Summary: summary, Checks: checks, Findings: findings, Outcome: OutcomePassed, Exit: ExitSuccess}
	switch {
	case summary.Operational != 0:
		report.Outcome, report.Exit = OutcomeIncomplete, ExitOperational
	case summary.Critical != 0 || summary.Errors != 0:
		report.Outcome, report.Exit = OutcomeFailed, ExitVerification
	case summary.Warnings != 0:
		report.Outcome, report.Exit = OutcomeWarning, ExitVerification
	}
	return report
}

func findingFieldsKey(fields []Field) string {
	var builder strings.Builder
	for _, field := range fields {
		builder.WriteString(field.Key)
		builder.WriteByte(0)
		builder.WriteString(field.Value)
		builder.WriteByte(0)
	}
	return builder.String()
}

func normalizeLayers(input []Layer) ([]Layer, error) {
	if len(input) == 0 {
		return nil, errors.New("at least one verification layer must be selected")
	}
	seen := make(map[Layer]struct{}, len(input))
	result := make([]Layer, 0, len(input))
	for _, layer := range input {
		if !validLayer(layer) {
			return nil, fmt.Errorf("unknown verification layer %q", layer)
		}
		if _, ok := seen[layer]; ok {
			continue
		}
		seen[layer] = struct{}{}
		result = append(result, layer)
	}
	sort.Slice(result, func(i, j int) bool { return layerRank(result[i]) < layerRank(result[j]) })
	return result, nil
}

func validLayer(layer Layer) bool {
	return layer == LayerL1 || layer == LayerL2 || layer == LayerL3 || layer == LayerL4
}

func fallbackLayer(layer Layer) Layer {
	if validLayer(layer) {
		return layer
	}
	return LayerL1
}

func validSeverity(severity Severity) bool {
	return severity == SeverityInfo || severity == SeverityWarning || severity == SeverityError || severity == SeverityCritical
}

func validCategory(category Category) bool {
	switch category {
	case CategoryIntegrity, CategoryDrift, CategoryConfidentiality, CategoryCoverage, CategoryOperational, CategoryEvidence:
		return true
	default:
		return false
	}
}

func validCheckID(id string) bool {
	if len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r == '-' || r == '_' || r == '.' || r == '/' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
}

func layerRank(layer Layer) int {
	switch layer {
	case LayerL1:
		return 1
	case LayerL2:
		return 2
	case LayerL3:
		return 3
	case LayerL4:
		return 4
	default:
		return 99
	}
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityInfo:
		return 1
	case SeverityWarning:
		return 2
	case SeverityError:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 99
	}
}
