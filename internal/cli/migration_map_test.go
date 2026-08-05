package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
)

var (
	legacyTargetRow = regexp.MustCompile(`^(ROOT|APT|YUM|DKR)-[0-9]+$`)
	legacyFamilyRow = regexp.MustCompile(`^(R|A|Y|D)[0-9][0-9]$`)
	inlineCode      = regexp.MustCompile("`([^`]+)`")
)

type migrationLedgerRow struct {
	id, target, category, replacement, disposition, rollback string
}

type migrationSelectorEvidence struct {
	rowID, commandSHA256, leavesSHA256 string
	commandOrdinal, leaves             int
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

	configPath := filepath.Join("..", "..", "docs", "migration", "fixtures", "pigsty-v1.yaml")
	goldenPath := filepath.Join("..", "..", "docs", "migration", "fixtures", "make-target-selector-golden.tsv")
	golden := readMigrationSelectorGolden(t, goldenPath)
	seenGolden := make(map[string]bool, len(golden))
	for _, row := range rows {
		commands := migrationCommands(row.replacement)
		if row.disposition == "sow-cli" && len(commands) == 0 {
			t.Fatalf("%s has no SOW command", row.id)
		}
		for index, command := range commands {
			evidence, hasSelectors := assertMigrationCommandSelectors(t, row.id, index+1, command, configPath)
			if !hasSelectors {
				continue
			}
			key := migrationSelectorGoldenKey(row.id, index+1)
			want, exists := golden[key]
			if !exists {
				t.Errorf("%s command %d has no exact physical-leaf golden; candidate=%s\t%d\t%s\t%d\t%s",
					row.id, index+1, evidence.rowID, evidence.commandOrdinal, evidence.commandSHA256, evidence.leaves, evidence.leavesSHA256)
				continue
			}
			seenGolden[key] = true
			if evidence != want {
				t.Errorf("%s command %d physical leaves drifted: got command=%s count=%d leaves=%s want command=%s count=%d leaves=%s",
					row.id, index+1, evidence.commandSHA256, evidence.leaves, evidence.leavesSHA256,
					want.commandSHA256, want.leaves, want.leavesSHA256)
			}
		}
	}
	for key := range golden {
		if !seenGolden[key] {
			t.Errorf("orphan exact physical-leaf golden %s", key)
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
	historical := read("..", "..", "design", "v0.2", "product-capabilities-v1.md")
	if !strings.Contains(historical, "sow sync --upstream pgdg-apt,pgdg-yum") ||
		!strings.Contains(historical, "docs/examples/sow-pgdg.yaml") {
		t.Fatal("retained V1 sync example is not bound to the shipped PGDG upstream configuration")
	}
	runbook := read("..", "..", "docs", "migration", "runbook.md")
	if !strings.Contains(runbook, "--target \"$STAGING_ROOT\" \\\n  --serving-base-url \"$STAGING_SERVING_BASE_URL\"") {
		t.Fatal("migration candidate materialize omits its explicit YUM serving base URL")
	}
	if !strings.Contains(runbook, "stable would end in /pro/v1/basic") {
		t.Fatal("migration candidate guidance does not bind stable YUM to its Basic serving base URL")
	}
}

func TestMigrationSelectorGoldenDetectsSameCountPhysicalLeafDrift(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "docs", "migration", "fixtures", "pigsty-v1.yaml")
	body, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	before := "id: asset-ext, type: asset, path: ext,"
	after := "id: asset-ext, type: asset, path: migration-ext-drift,"
	if strings.Count(string(body), before) != 1 {
		t.Fatal("asset-ext physical fixture declaration is unavailable or ambiguous")
	}
	drifted := strings.Replace(string(body), before, after, 1)
	configPath := filepath.Join(t.TempDir(), "sow.yaml")
	if err := os.WriteFile(configPath, []byte(drifted), 0o600); err != nil {
		t.Fatal(err)
	}
	command := "sow publish --repo asset-ext --target cf"
	got, selected := assertMigrationCommandSelectors(t, "ROOT-06", 1, command, configPath)
	if !selected {
		t.Fatal("same-count drift fixture unexpectedly lost its selector")
	}
	want := readMigrationSelectorGolden(t, filepath.Join("..", "..", "docs", "migration", "fixtures", "make-target-selector-golden.tsv"))[migrationSelectorGoldenKey("ROOT-06", 1)]
	if got.leaves != want.leaves {
		t.Fatalf("same-count drift changed count: got=%d want=%d", got.leaves, want.leaves)
	}
	if got.commandSHA256 != want.commandSHA256 {
		t.Fatal("same command changed its command digest")
	}
	if got.leavesSHA256 == want.leavesSHA256 {
		t.Fatal("same-count physical path drift escaped exact-leaf digest")
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

func assertMigrationCommandSelectors(t *testing.T, id string, ordinal int, command, configPath string) (migrationSelectorEvidence, bool) {
	t.Helper()
	words := strings.Fields(command)
	if len(words) < 2 || words[0] != "sow" {
		t.Fatalf("%s command %d is not a SOW command: %q", id, ordinal, command)
	}
	if words[1] == "compatibility" {
		leaves := assertMigrationCompatibilityCommand(t, id, ordinal, words, configPath)
		commandDigest := sha256.Sum256([]byte(command))
		leavesDigest := sha256.Sum256([]byte(strings.Join(leaves, "\n") + "\n"))
		return migrationSelectorEvidence{
			rowID: id, commandOrdinal: ordinal, leaves: len(leaves),
			commandSHA256: hex.EncodeToString(commandDigest[:]), leavesSHA256: hex.EncodeToString(leavesDigest[:]),
		}, true
	}
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
		t.Fatalf("%s selector does not resolve against the physical Pigsty-v1 config: %q: %v", id, command, err)
	}
	hasSelectors := flagValue("--repo") != "" || flagValue("--os") != "" || flagValue("--arch") != ""
	if !hasSelectors {
		return migrationSelectorEvidence{}, false
	}
	if len(selected) == 0 {
		t.Fatalf("%s command=%q resolves to zero physical repositories", id, command)
	}
	if words[1] == "publish" {
		for _, target := range strings.Split(flagValue("--target"), ",") {
			if target == "" {
				continue
			}
			for _, repo := range selected {
				if !repo.PublishesToTarget(target) {
					t.Fatalf("%s command=%q selects repo %s outside target %s affinity", id, command, repo.ID, target)
				}
			}
		}
	}
	leaves := migrationPhysicalLeaves(t, selected)
	commandDigest := sha256.Sum256([]byte(command))
	leavesDigest := sha256.Sum256([]byte(strings.Join(leaves, "\n") + "\n"))
	return migrationSelectorEvidence{
		rowID: id, commandOrdinal: ordinal, leaves: len(leaves),
		commandSHA256: hex.EncodeToString(commandDigest[:]), leavesSHA256: hex.EncodeToString(leavesDigest[:]),
	}, true
}

func assertMigrationCompatibilityCommand(t *testing.T, id string, ordinal int, words []string, configPath string) []string {
	t.Helper()
	if len(words) < 4 || words[0] != "sow" || words[1] != "compatibility" {
		t.Fatalf("%s command %d has an incomplete compatibility command", id, ordinal)
	}
	allowed := map[string]bool{"yum-adopt": true, "yum-candidate": true, "yum-freeze": true, "yum-cutover": true, "yum-rollback": true}
	if !allowed[words[2]] {
		t.Fatalf("%s command %d uses unknown compatibility verb %q", id, ordinal, words[2])
	}
	if migrationCommandFlagValue(words, "--id") == "" {
		t.Fatalf("%s command %d compatibility workflow omits --id", id, ordinal)
	}
	if words[2] == "yum-candidate" && migrationCommandFlagValue(words, "--output") == "" {
		t.Fatalf("%s command %d yum-candidate omits --output", id, ordinal)
	}
	for _, forbidden := range []string{"--repo", "--os", "--arch"} {
		if migrationCommandFlagValue(words, forbidden) != "" {
			t.Fatalf("%s command %d compatibility workflow uses ordinary selector %s", id, ordinal, forbidden)
		}
	}
	cfg, err := config.Load(configPath, t.TempDir())
	if err != nil {
		t.Fatalf("%s command %d cannot load physical compatibility contract: %v", id, ordinal, err)
	}
	projections, err := migrationCompatibilityCommandProjections(words, cfg)
	if err != nil {
		t.Fatalf("%s command %d cannot resolve physical compatibility projection: %v", id, ordinal, err)
	}
	leaves := make([]string, 0, len(projections))
	for _, projection := range projections {
		leaves = append(leaves, migrationLeafIdentity(
			"compatibility", projection.ID, projection.Root, projection.Mode, projection.Carrier,
			projection.Source.Repo, projection.Source.View, projection.Source.OS, projection.Source.Arch, projection.Source.Commit,
		))
	}
	sort.Strings(leaves)
	if len(leaves) == 0 {
		t.Fatalf("%s command %d resolves to zero physical compatibility projections", id, ordinal)
	}
	return leaves
}

func migrationCommandFlagValue(words []string, name string) string {
	for index, word := range words {
		if word == name && index+1 < len(words) && !strings.HasPrefix(words[index+1], "--") {
			return words[index+1]
		}
		if strings.HasPrefix(word, name+"=") {
			return strings.TrimPrefix(word, name+"=")
		}
	}
	return ""
}

func migrationCompatibilityCommandProjections(words []string, cfg *config.Config) ([]config.YUMCompatibilityProjection, error) {
	value := migrationCommandFlagValue(words, "--id")
	if value == "<id>" {
		projections := config.SortedYUMCompatibilityProjections(cfg.CompatibilityProjections)
		if len(projections) == 0 {
			return nil, fmt.Errorf("physical config declares no compatibility projections")
		}
		return projections, nil
	}
	if value == "" {
		return nil, fmt.Errorf("missing --id")
	}
	projection, exists, err := config.YUMCompatibilityProjectionByID(cfg.CompatibilityProjections, value)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("compatibility projection %q is unavailable", value)
	}
	return []config.YUMCompatibilityProjection{projection}, nil
}

func migrationPhysicalLeaves(t *testing.T, repos []config.Repo) []string {
	t.Helper()
	var leaves []string
	for _, repo := range repos {
		switch repo.Type {
		case "apt":
			if repo.APT == nil {
				t.Fatalf("selected APT repo %s has no APT contract", repo.ID)
			}
			for _, suite := range repo.APT.Suites {
				for _, component := range repo.APT.ComponentsForSuite(suite) {
					for _, arch := range repo.Arches {
						leaf := path.Join(repo.Path, "dists", suite, component, "binary-"+arch)
						leaves = append(leaves, migrationLeafIdentity("apt", repo.ID, suite, component, arch, leaf, leaf, repo.LifecycleForSuite(suite)))
					}
				}
			}
		case "yum":
			if repo.YUM == nil {
				t.Fatalf("selected YUM repo %s has no YUM contract", repo.ID)
			}
			osValues := strings.Join(repo.OSSelectorValues(), ",")
			for _, arch := range repo.Arches {
				leaf, err := repo.PathForArch(arch)
				if err != nil {
					t.Fatalf("expand selected YUM repo %s/%s: %v", repo.ID, arch, err)
				}
				leaves = append(leaves, migrationLeafIdentity("yum", repo.ID, osValues, "-", arch, leaf, leaf, repo.OS.Lifecycle))
			}
		case "asset":
			leaves = append(leaves, migrationLeafIdentity("asset", repo.ID, "all", "-", "all", repo.Path, repo.AssetPublicRoot(), repo.DefaultPool))
		default:
			t.Fatalf("selected repo %s has unknown type %s", repo.ID, repo.Type)
		}
	}
	sort.Strings(leaves)
	if len(leaves) == 0 {
		t.Fatal("selector expanded to zero physical leaves")
	}
	for index := 1; index < len(leaves); index++ {
		if leaves[index] == leaves[index-1] {
			t.Fatalf("selector expanded duplicate physical leaf %q", leaves[index])
		}
	}
	return leaves
}

func migrationLeafIdentity(fields ...string) string {
	return strings.Join(fields, "\x00")
}

func migrationSelectorGoldenKey(id string, ordinal int) string {
	return id + "#" + strconv.Itoa(ordinal)
}

func readMigrationSelectorGolden(t *testing.T, filename string) map[string]migrationSelectorEvidence {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result := make(map[string]migrationSelectorEvidence)
	scanner := bufio.NewScanner(file)
	line, schema := 0, false
	previous := ""
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if text == "# schema=sow-migration-selector-golden/v1" {
			if schema {
				t.Fatalf("%s:%d duplicate schema", filename, line)
			}
			schema = true
			continue
		}
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) != 5 {
			t.Fatalf("%s:%d expected 5 tab-separated fields", filename, line)
		}
		ordinal, ordinalErr := strconv.Atoi(fields[1])
		leaves, leavesErr := strconv.Atoi(fields[3])
		if ordinalErr != nil || ordinal < 1 || leavesErr != nil || leaves < 1 {
			t.Fatalf("%s:%d invalid ordinal or leaf count", filename, line)
		}
		for _, digest := range []string{fields[2], fields[4]} {
			decoded, decodeErr := hex.DecodeString(digest)
			if decodeErr != nil || len(decoded) != sha256.Size || digest != strings.ToLower(digest) {
				t.Fatalf("%s:%d invalid SHA-256 %q", filename, line, digest)
			}
		}
		key := migrationSelectorGoldenKey(fields[0], ordinal)
		if key <= previous {
			t.Fatalf("%s:%d golden rows are duplicate or not canonically sorted: %s", filename, line, key)
		}
		previous = key
		result[key] = migrationSelectorEvidence{rowID: fields[0], commandOrdinal: ordinal, commandSHA256: fields[2], leaves: leaves, leavesSHA256: fields[4]}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !schema || len(result) == 0 {
		t.Fatalf("%s is missing its schema or exact leaf rows", filename)
	}
	return result
}
