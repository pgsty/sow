package cli

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	legacyTargetRow = regexp.MustCompile(`^(ROOT|APT|YUM|DKR)-[0-9]+$`)
	legacyFamilyRow = regexp.MustCompile(`^(R|A|Y|D)[0-9][0-9]$`)
	inlineCode      = regexp.MustCompile("`([^`]+)`")
)

type migrationLedgerRow struct {
	id, target, category, replacement, disposition, rollback string
}

func TestLegacyMigrationMapClosesFamiliesAndSelectors(t *testing.T) {
	mapPath := filepath.Join("..", "..", "docs", "migration", "make-target-map.md")
	rows, families := readMigrationLedger(t, mapPath)
	if len(rows) != 176 || len(families) != 44 {
		t.Fatalf("targets=%d families=%d", len(rows), len(families))
	}
	wantTargets := make(map[string]string, len(rows))
	aliasRows, aliasCLI := 0, 0
	for _, row := range rows {
		prefix := strings.SplitN(row.id, "-", 2)[0]
		wantTargets[prefix+"\x00"+row.target] = row.id
		if isLegacyAliasCategory(row.category) {
			aliasRows++
			if row.disposition == "sow-cli" {
				aliasCLI++
			}
		}
	}
	seen := make(map[string]string, len(rows))
	for family, targets := range families {
		prefix := map[string]string{"R": "ROOT", "A": "APT", "Y": "YUM", "D": "DKR"}[family[:1]]
		for _, target := range targets {
			key := prefix + "\x00" + target
			if previous := seen[key]; previous != "" {
				t.Fatalf("target %s belongs to both %s and %s", key, previous, family)
			}
			seen[key] = family
		}
	}
	for key, id := range wantTargets {
		if seen[key] == "" {
			t.Fatalf("target %s (%s) is absent from the 44-family partition", key, id)
		}
	}
	for key, family := range seen {
		if wantTargets[key] == "" {
			t.Fatalf("family %s contains unknown target %s", family, key)
		}
	}
	if aliasRows != 46 || aliasCLI != 36 {
		t.Fatalf("alias-like rows=%d sow-cli=%d", aliasRows, aliasCLI)
	}

	configPath := filepath.Join("..", "..", "docs", "migration", "fixtures", "selector-matrix.yaml")
	for _, row := range rows {
		commands := migrationCommands(row.replacement)
		if row.disposition == "sow-cli" && len(commands) == 0 {
			t.Fatalf("%s has no SOW command", row.id)
		}
		for _, command := range commands {
			assertMigrationCommandSelectors(t, row.id, command, configPath)
		}
	}
}

func TestOperatorExamplesBindYUMExportsAndConfiguredUpstreams(t *testing.T) {
	read := func(relative ...string) string {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(relative...))
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	readme := read("..", "..", "README.md")
	if !strings.Contains(readme, "materialize stable --config sow.yaml --target export/stable") ||
		!strings.Contains(readme, "--serving-base-url https://repo.example/pro/v1/basic") {
		t.Fatal("README explicit stable YUM export does not bind its Basic serving base URL")
	}
	if !strings.Contains(readme, "--upstream pgdg-apt,pgdg-yum") ||
		!strings.Contains(readme, "docs/examples/sow-pgdg.yaml") {
		t.Fatal("README sync example is not bound to the shipped PGDG upstream configuration")
	}
	runbook := read("..", "..", "docs", "migration", "runbook.md")
	if !strings.Contains(runbook, "--target \"$STAGING_ROOT\" \\\n  --serving-base-url \"$STAGING_SERVING_BASE_URL\"") {
		t.Fatal("migration candidate materialize omits its explicit YUM serving base URL")
	}
}

func readMigrationLedger(t *testing.T, filename string) ([]migrationLedgerRow, map[string][]string) {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var rows []migrationLedgerRow
	families := make(map[string][]string)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "|")
		if len(parts) < 3 {
			continue
		}
		id := strings.TrimSpace(parts[1])
		switch {
		case legacyTargetRow.MatchString(id):
			if len(parts) < 10 {
				t.Fatalf("truncated target row %s", id)
			}
			rows = append(rows, migrationLedgerRow{
				id: id, target: trimCode(parts[2]), category: trimCode(parts[3]),
				replacement: strings.TrimSpace(parts[7]), disposition: strings.TrimSpace(parts[8]), rollback: strings.TrimSpace(parts[9]),
			})
		case legacyFamilyRow.MatchString(id):
			words := strings.Fields(trimCode(parts[2]))
			if len(words) < 2 {
				t.Fatalf("family %s has no targets", id)
			}
			families[id] = append([]string(nil), words[1:]...)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return rows, families
}

func trimCode(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), "`", "")
}

func isLegacyAliasCategory(category string) bool {
	for _, fragment := range []string{"别名", "编排", "入口", "快捷"} {
		if strings.Contains(category, fragment) {
			return true
		}
	}
	return false
}

func migrationCommands(replacement string) []string {
	var commands []string
	for _, match := range inlineCode.FindAllStringSubmatch(replacement, -1) {
		if strings.HasPrefix(match[1], "sow ") {
			commands = append(commands, match[1])
		}
	}
	return commands
}

func assertMigrationCommandSelectors(t *testing.T, id, command, configPath string) {
	t.Helper()
	words := strings.Fields(command)
	values := commonFlags{configPath: configPath, root: t.TempDir(), workers: 1, chunk: 1}
	flagValue := func(name string) string {
		for i, word := range words {
			if word == name && i+1 < len(words) {
				return words[i+1]
			}
			if strings.HasPrefix(word, name+"=") {
				return strings.TrimPrefix(word, name+"=")
			}
		}
		return ""
	}
	for _, selector := range []struct {
		value       string
		destination *csvFlag
	}{
		{flagValue("--repo"), &values.repos},
		{flagValue("--os"), &values.oses},
		{flagValue("--arch"), &values.arches},
	} {
		value, destination := selector.value, selector.destination
		if value != "" {
			if err := destination.Set(value); err != nil {
				t.Fatalf("%s %q: %v", id, command, err)
			}
		}
	}
	_, selected, err := loadAndSelect(values)
	if err != nil {
		t.Fatalf("%s selector does not resolve against selector-matrix.yaml: %q: %v", id, command, err)
	}
	if len(values.repos.values()) == 0 {
		return
	}
	got := make([]string, 0, len(selected))
	for _, repo := range selected {
		got = append(got, repo.ID)
	}
	want := append([]string(nil), values.repos.values()...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s command=%q selected=%v want=%v", id, command, got, want)
	}
}
