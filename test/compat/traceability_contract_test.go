package compat_test

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type traceabilityCategory struct {
	label string
	ids   []string
}

type traceabilitySummary struct {
	total  int
	counts map[string]int
}

var traceabilitySummaryCountPattern = regexp.MustCompile(`([0-9]+) ` + "`" + `([^` + "`" + `]+)` + "`")

func TestRequirementsTraceabilityLedgerIsCompleteAndInternallyConsistent(t *testing.T) {
	t.Parallel()
	root := findModuleRoot(t)
	path := filepath.Join(root, "docs", "requirements-traceability.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 4<<20 {
		t.Fatalf("requirements traceability ledger exceeds 4 MiB: %d", len(body))
	}
	if err := validateRequirementsTraceabilityLedger(body); err != nil {
		t.Fatal(err)
	}
}

func TestRequirementsTraceabilityLedgerRejectsMissingUndefinedStaleAndFalseCompletion(t *testing.T) {
	t.Parallel()
	root := findModuleRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "docs", "requirements-traceability.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "missing requirement",
			mutate: func(input []byte) []byte {
				return replaceTraceabilityOnce(t, input, "| FR-42 |", "| FR-99 |")
			},
		},
		{
			name: "undefined status",
			mutate: func(input []byte) []byte {
				return replaceTraceabilityLineOnce(t, input, "| NFR-07 |", "`实现中/未验证`", "`未知`")
			},
		},
		{
			name: "stale summary",
			mutate: func(input []byte) []byte {
				return replaceTraceabilityLineOnce(t, input, "| NFR-01–NFR-09 |", "5 `已验证`", "4 `已验证`")
			},
		},
		{
			name: "false completion",
			mutate: func(input []byte) []byte {
				return replaceTraceabilityOnce(t, input, "Goal **不能完成**", "Goal **完成**")
			},
		},
	} {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			if err := validateRequirementsTraceabilityLedger(fixture.mutate(body)); err == nil {
				t.Fatal("traceability ledger validator accepted an inconsistent fixture")
			}
		})
	}
}

func validateRequirementsTraceabilityLedger(body []byte) error {
	categories := requiredTraceabilityCategories()
	idCategory := make(map[string]string)
	for _, category := range categories {
		for _, id := range category.ids {
			if prior := idCategory[id]; prior != "" {
				return fmt.Errorf("traceability contract defines duplicate expected ID %s", id)
			}
			idCategory[id] = category.label
		}
	}

	taxonomy := make(map[string]bool)
	statusByID := make(map[string]string)
	summaries := make(map[string]traceabilitySummary)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		cells := traceabilityMarkdownCells(scanner.Text())
		if len(cells) < 2 {
			continue
		}
		if status, ok := traceabilityStatusCell(cells[0]); ok && len(cells) == 2 {
			taxonomy[status] = true
			continue
		}
		if category := traceabilityCategoryByLabel(categories, cells[0]); category != nil {
			if _, duplicate := summaries[category.label]; duplicate {
				return fmt.Errorf("traceability summary category %q is duplicated", category.label)
			}
			if len(cells) != 3 {
				return fmt.Errorf("traceability summary category %q has %d cells", category.label, len(cells))
			}
			total, err := strconv.Atoi(cells[1])
			if err != nil {
				return fmt.Errorf("traceability summary category %q has invalid total %q", category.label, cells[1])
			}
			counts, err := parseTraceabilitySummaryCounts(cells[2])
			if err != nil {
				return fmt.Errorf("traceability summary category %q: %w", category.label, err)
			}
			summaries[category.label] = traceabilitySummary{total: total, counts: counts}
			continue
		}
		if _, expected := idCategory[cells[0]]; !expected {
			continue
		}
		if _, duplicate := statusByID[cells[0]]; duplicate {
			return fmt.Errorf("traceability requirement %s is duplicated", cells[0])
		}
		status := ""
		for _, cell := range cells[1:] {
			candidate, ok := traceabilityStatusCell(cell)
			if !ok {
				continue
			}
			if status != "" {
				return fmt.Errorf("traceability requirement %s contains multiple status cells", cells[0])
			}
			status = candidate
		}
		if status == "" {
			return fmt.Errorf("traceability requirement %s has no exact status cell", cells[0])
		}
		statusByID[cells[0]] = status
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan traceability ledger: %w", err)
	}

	if len(taxonomy) == 0 {
		return fmt.Errorf("traceability status taxonomy is absent")
	}
	actualCounts := make(map[string]map[string]int)
	for id, category := range idCategory {
		status, exists := statusByID[id]
		if !exists {
			return fmt.Errorf("traceability requirement %s is missing", id)
		}
		if !taxonomy[status] {
			return fmt.Errorf("traceability requirement %s uses undefined status %q", id, status)
		}
		if actualCounts[category] == nil {
			actualCounts[category] = make(map[string]int)
		}
		actualCounts[category][status]++
	}
	if len(statusByID) != len(idCategory) {
		return fmt.Errorf("traceability requirement count = %d, want %d", len(statusByID), len(idCategory))
	}
	for _, category := range categories {
		summary, exists := summaries[category.label]
		if !exists {
			return fmt.Errorf("traceability summary category %q is missing", category.label)
		}
		if summary.total != len(category.ids) {
			return fmt.Errorf("traceability summary category %q total = %d, want %d", category.label, summary.total, len(category.ids))
		}
		if err := compareTraceabilityCounts(category.label, summary.counts, actualCounts[category.label]); err != nil {
			return err
		}
	}
	if len(summaries) != len(categories) {
		return fmt.Errorf("traceability summary category count = %d, want %d", len(summaries), len(categories))
	}

	incomplete := false
	for _, status := range statusByID {
		switch status {
		case "实现中", "未实现", "未验证", "受阻", "已实现/未验证", "实现中/未验证":
			incomplete = true
		}
	}
	if incomplete && !strings.Contains(string(body), "Goal **不能完成**") {
		return fmt.Errorf("traceability ledger has incomplete requirements but does not fail closed on Goal completion")
	}
	return nil
}

func replaceTraceabilityOnce(t *testing.T, body []byte, old, replacement string) []byte {
	t.Helper()
	if strings.Count(string(body), old) != 1 {
		t.Fatalf("traceability fixture marker %q is not unique", old)
	}
	return []byte(strings.Replace(string(body), old, replacement, 1))
}

func replaceTraceabilityLineOnce(t *testing.T, body []byte, prefix, old, replacement string) []byte {
	t.Helper()
	lines := strings.Split(string(body), "\n")
	found := 0
	for index := range lines {
		if !strings.HasPrefix(lines[index], prefix) {
			continue
		}
		found++
		if strings.Count(lines[index], old) != 1 {
			t.Fatalf("traceability line %q does not contain one %q marker", prefix, old)
		}
		lines[index] = strings.Replace(lines[index], old, replacement, 1)
	}
	if found != 1 {
		t.Fatalf("traceability fixture line %q count = %d", prefix, found)
	}
	return []byte(strings.Join(lines, "\n"))
}

func traceabilityMarkdownCells(line string) []string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
		return nil
	}
	raw := strings.Split(strings.Trim(line, "|"), "|")
	cells := make([]string, len(raw))
	for index := range raw {
		cells[index] = strings.TrimSpace(raw[index])
	}
	return cells
}

func traceabilityStatusCell(cell string) (string, bool) {
	if len(cell) < 3 || cell[0] != '`' || cell[len(cell)-1] != '`' {
		return "", false
	}
	status := cell[1 : len(cell)-1]
	if status == "" || strings.ContainsRune(status, '`') {
		return "", false
	}
	return status, true
}

func parseTraceabilitySummaryCounts(cell string) (map[string]int, error) {
	matches := traceabilitySummaryCountPattern.FindAllStringSubmatch(cell, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("status counts are absent")
	}
	counts := make(map[string]int)
	for _, match := range matches {
		count, err := strconv.Atoi(match[1])
		if err != nil || count <= 0 {
			return nil, fmt.Errorf("invalid status count %q", match[1])
		}
		if _, duplicate := counts[match[2]]; duplicate {
			return nil, fmt.Errorf("status %q is duplicated", match[2])
		}
		counts[match[2]] = count
	}
	return counts, nil
}

func compareTraceabilityCounts(category string, summary, actual map[string]int) error {
	for status, count := range actual {
		if summary[status] != count {
			return fmt.Errorf("traceability summary category %q status %q = %d, want %d", category, status, summary[status], count)
		}
	}
	for status, count := range summary {
		if actual[status] != count {
			return fmt.Errorf("traceability summary category %q contains stale status %q count %d", category, status, count)
		}
	}
	return nil
}

func traceabilityCategoryByLabel(categories []traceabilityCategory, label string) *traceabilityCategory {
	for index := range categories {
		if categories[index].label == label {
			return &categories[index]
		}
	}
	return nil
}

func requiredTraceabilityCategories() []traceabilityCategory {
	return []traceabilityCategory{
		{label: "G1–G6", ids: traceabilityIDs("G", 1, 6, false)},
		{label: "反指标", ids: traceabilityIDs("ANTI", 1, 3, true)},
		{label: "FR-01–FR-42", ids: traceabilityIDs("FR", 1, 42, true)},
		{label: "NFR-01–NFR-09", ids: traceabilityIDs("NFR", 1, 9, true)},
		{label: "FZ-01–FZ-09", ids: traceabilityIDs("FZ", 1, 9, true)},
		{label: "COMP-01–COMP-05", ids: traceabilityIDs("COMP", 1, 5, true)},
		{label: "TECH-01–TECH-10", ids: traceabilityIDs("TECH", 1, 10, true)},
		{label: "OUT-01–OUT-05", ids: traceabilityIDs("OUT", 1, 5, true)},
		{label: "MIG-01–MIG-08", ids: traceabilityIDs("MIG", 1, 8, true)},
		{label: "RISK-01–RISK-06", ids: traceabilityIDs("RISK", 1, 6, true)},
		{label: "POC-01–POC-07", ids: traceabilityIDs("POC", 1, 7, true)},
		{label: "OQ-1–OQ-5", ids: traceabilityIDs("OQ", 1, 5, false)},
	}
}

func traceabilityIDs(prefix string, first, last int, padded bool) []string {
	ids := make([]string, 0, last-first+1)
	for number := first; number <= last; number++ {
		switch {
		case prefix == "G":
			ids = append(ids, fmt.Sprintf("G%d", number))
		case padded:
			ids = append(ids, fmt.Sprintf("%s-%02d", prefix, number))
		default:
			ids = append(ids, fmt.Sprintf("%s-%d", prefix, number))
		}
	}
	return ids
}
