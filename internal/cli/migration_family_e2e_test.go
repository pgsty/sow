package cli

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
)

const migrationFamilyContractSchema = "# schema=sow-migration-family-e2e/v1"

type migrationFamilyContract struct {
	family       string
	dispositions []string
	coverage     string
	evidence     []string
	boundary     string
}

type migrationEvidenceCapability struct {
	verbs               map[string]bool
	repoType            map[string]bool
	compatibilityArches map[string]bool
	provider            bool
}

var migrationEvidenceCapabilities = map[string]migrationEvidenceCapability{
	"TestInitAndFSCKEndToEnd": evidenceCapability(
		[]string{"init", "fsck"}, []string{"asset"}, false,
	),
	"TestInitAdoptContentAssetsIsZeroRewriteAtomicAndIdempotent": evidenceCapability(
		[]string{"init"}, []string{"asset"}, false,
	),
	"TestInitAdoptContentRejectsGatedPublicAndAllowsStable": evidenceCapability(
		[]string{"init"}, []string{"asset"}, false,
	),
	"TestInitAdoptContentPigstyV1SuiteNestedAPTAndFlatYUM": evidenceCapability(
		[]string{"init", "materialize", "fsck"}, []string{"apt", "yum"}, false,
	),
	"TestInitAdoptContentSynthetic33RepoGeneralization": evidenceCapability(
		[]string{"init", "materialize", "fsck"}, []string{"asset", "apt", "yum"}, false,
	),
	"TestDEBAddBuildsSignedByHashRepositoryFromExternalPackage": evidenceCapability(
		[]string{"add", "rm", "verify"}, []string{"apt"}, false,
	),
	"TestRPMAddBuildsSignedZstdRepositoryFromExternalPackage": evidenceCapability(
		[]string{"add", "rm", "verify"}, []string{"yum"}, false,
	),
	"TestGCDryRunConfirmationAndHistoryRoots": evidenceCapability(
		[]string{"gc"}, []string{"asset", "apt", "yum"}, false,
	),
	"TestSyncAPTEndToEndPreservesCanonicalProvenanceAndNeverDeletes": evidenceCapability(
		[]string{"sync"}, []string{"apt"}, false,
	),
	"TestSyncYUMEndToEndPreservesCanonicalProvenanceAndNeverDeletes": evidenceCapability(
		[]string{"sync"}, []string{"yum"}, false,
	),
	"TestMaterializeCLIProducesExactHardlinkTree": evidenceCapability(
		[]string{"materialize"}, []string{"asset"}, false,
	),
	"TestMaterializeNginxAndEdgeCompatibilityStateMachineThroughRollback": compatibilityEvidenceCapability("x86_64"),
	"TestYUMCompatibilityAArch64StateMachineThroughRollback":              compatibilityEvidenceCapability("aarch64"),
	"TestPublishCLIUsesRealProviderProtocolAndAdvancesRemoteRefLast": evidenceCapability(
		[]string{"add", "promote", "publish"}, []string{"asset"}, true,
	),
	"TestPublishCLIStableUsesGatedNamespaceAndScopedBasicVerification": evidenceCapability(
		[]string{"add", "publish"}, []string{"asset"}, true,
	),
	"TestPublishCLIUploadsRealAPTAndYUMGenerationClosures": evidenceCapability(
		[]string{"add", "promote", "publish"}, []string{"apt", "yum"}, true,
	),
}

func TestLegacyMigrationFixturesUseCanonical33RepoUniverse(t *testing.T) {
	mapPath := filepath.Join("..", "..", "docs", "migration", "make-target-map.md")
	rows, _ := readMigrationLedger(t, mapPath)
	selectorPath := filepath.Join("..", "..", "docs", "migration", "fixtures", "selector-matrix.yaml")
	subsetPath := filepath.Join("..", "..", "docs", "migration", "fixtures", "pigsty-v1-synthetic.yaml")
	physicalPath := filepath.Join("..", "..", "docs", "migration", "fixtures", "pigsty-v1.yaml")
	selector := loadMigrationFixture(t, selectorPath)
	subset := loadMigrationFixture(t, subsetPath)
	physical := loadMigrationFixture(t, physicalPath)

	selectorIDs := repoIDSet(selector.Repos)
	if len(selectorIDs) != 33 {
		t.Fatalf("selector fixture repositories=%d want=33", len(selectorIDs))
	}
	commandIDs := make(map[string]bool)
	for _, row := range rows {
		for _, command := range migrationCommands(row.replacement) {
			for _, id := range migrationCommandRepoIDs(command) {
				commandIDs[id] = true
			}
		}
	}
	for _, id := range sortedKeys(commandIDs) {
		if _, err := physical.ExpandRepoSelectors([]string{id}); err != nil {
			t.Errorf("migration command selector %q does not resolve in the physical Pigsty-v1 contract: %v", id, err)
		}
	}
	for _, forbidden := range []string{"yum-infra", "yum-ivory"} {
		if commandIDs[forbidden] {
			t.Errorf("migration command universe retained forbidden ordinary selector %q", forbidden)
		}
	}

	wantPhysical := map[string]string{
		"pkg-pig":            "pkg/pig",
		"apt-pgsql-focal":    "apt/pgsql/focal",
		"apt-pgsql-jammy":    "apt/pgsql/jammy",
		"apt-pgsql-noble":    "apt/pgsql/noble",
		"apt-pgsql-resolute": "apt/pgsql/resolute",
		"apt-pgsql-bullseye": "apt/pgsql/bullseye",
		"apt-pgsql-bookworm": "apt/pgsql/bookworm",
		"apt-pgsql-trixie":   "apt/pgsql/trixie",
		"yum-pgsql-el7":      "yum/pgsql/el7.{arch}",
		"yum-pgsql-el8":      "yum/pgsql/el8.{arch}",
		"yum-pgsql-el9":      "yum/pgsql/el9.{arch}",
		"yum-pgsql-el10":     "yum/pgsql/el10.{arch}",
	}
	if len(subset.Repos) != len(wantPhysical) {
		t.Fatalf("synthetic physical-shape subset repositories=%d want=%d", len(subset.Repos), len(wantPhysical))
	}
	for _, repo := range subset.Repos {
		wantPath, exists := wantPhysical[repo.ID]
		if !exists {
			t.Errorf("synthetic subset has non-canonical repository id %q", repo.ID)
			continue
		}
		if repo.Path != wantPath {
			t.Errorf("synthetic subset repo %s path=%q want=%q", repo.ID, repo.Path, wantPath)
		}
		if !selectorIDs[repo.ID] {
			t.Errorf("synthetic subset repo %s is absent from the 33-repo selector universe", repo.ID)
		}
	}
}

func TestLegacyMigrationFamilyE2EContract(t *testing.T) {
	mapPath := filepath.Join("..", "..", "docs", "migration", "make-target-map.md")
	contractPath := filepath.Join("..", "..", "docs", "migration", "fixtures", "family-e2e.tsv")
	if override := os.Getenv("SOW_MIGRATION_FAMILY_CONTRACT"); override != "" {
		contractPath = override
	}
	selectorPath := filepath.Join("..", "..", "docs", "migration", "fixtures", "pigsty-v1.yaml")
	rows, families := readMigrationLedger(t, mapPath)
	contracts := readMigrationFamilyContracts(t, contractPath)
	selector := loadMigrationFixture(t, selectorPath)
	ledgerFamilies := migrationRowsByFamily(t, rows, families)

	if len(contracts) != 44 || len(ledgerFamilies) != 44 {
		t.Fatalf("family contracts=%d ledger families=%d want=44", len(contracts), len(ledgerFamilies))
	}
	assertMigrationEvidenceTestsExist(t)
	referencedTests := make(map[string]bool)
	for _, contract := range contracts {
		for _, item := range contract.evidence {
			if strings.HasPrefix(item, "Test") {
				referencedTests[item] = true
			}
		}
	}
	for name := range migrationEvidenceCapabilities {
		if !referencedTests[name] {
			t.Errorf("migration evidence capability %s is not bound to any operation family", name)
		}
	}
	for family, familyRows := range ledgerFamilies {
		contract, exists := contracts[family]
		if !exists {
			t.Errorf("family %s has no E2E/disposition contract", family)
			continue
		}
		wantDispositions := uniqueSortedStrings(migrationRowDispositions(familyRows))
		if strings.Join(contract.dispositions, ",") != strings.Join(wantDispositions, ",") {
			t.Errorf("family %s dispositions=%v want=%v", family, contract.dispositions, wantDispositions)
		}
		evidenceSet := migrationStringSet(contract.evidence)
		for _, item := range contract.evidence {
			switch {
			case strings.HasPrefix(item, "Test"):
				if _, exists := migrationEvidenceCapabilities[item]; !exists {
					t.Errorf("family %s references unclassified E2E test %s", family, item)
				}
			case strings.HasPrefix(item, "contract:"):
				disposition := strings.TrimPrefix(item, "contract:")
				if !containsString([]string{"retire", "policy-reject", "external-handoff", "migration-only"}, disposition) {
					t.Errorf("family %s references unknown disposition contract %s", family, item)
				}
			default:
				t.Errorf("family %s has unknown evidence token %s", family, item)
			}
		}
		for _, disposition := range wantDispositions {
			if disposition == "sow-cli" {
				continue
			}
			if token := "contract:" + disposition; !evidenceSet[token] {
				t.Errorf("family %s disposition %s lacks explicit %s evidence", family, disposition, token)
			}
		}

		hasSOW := containsString(wantDispositions, "sow-cli")
		if !hasSOW {
			if contract.coverage != "disposition-contract" {
				t.Errorf("family %s has no sow-cli rows but coverage=%q", family, contract.coverage)
			}
			for _, item := range contract.evidence {
				if strings.HasPrefix(item, "Test") {
					t.Errorf("family %s disposition-only contract improperly claims CLI test %s", family, item)
				}
			}
			continue
		}
		if contract.coverage == "disposition-contract" {
			t.Errorf("family %s has sow-cli rows but no executable local evidence mode", family)
			continue
		}
		if migrationRowsContainVerb(familyRows, "publish") && !strings.Contains(contract.coverage, "provider-protocol") {
			t.Errorf("family %s contains publish but coverage=%q omits provider-protocol", family, contract.coverage)
		}
		assertMigrationFamilyCommandsCovered(t, family, familyRows, contract, selector)
	}
	for family := range contracts {
		if _, exists := ledgerFamilies[family]; !exists {
			t.Errorf("E2E contract contains unknown family %s", family)
		}
	}
}

func evidenceCapability(verbs, repoTypes []string, provider bool) migrationEvidenceCapability {
	return migrationEvidenceCapability{verbs: migrationStringSet(verbs), repoType: migrationStringSet(repoTypes), provider: provider}
}

func compatibilityEvidenceCapability(arch string) migrationEvidenceCapability {
	capability := evidenceCapability(
		[]string{"compatibility/yum-adopt", "compatibility/yum-candidate", "compatibility/yum-freeze", "compatibility/yum-cutover", "compatibility/yum-rollback"},
		[]string{"yum"}, false,
	)
	capability.compatibilityArches = map[string]bool{arch: true}
	return capability
}

func loadMigrationFixture(t *testing.T, filename string) *config.Config {
	t.Helper()
	loaded, err := config.Load(filename, t.TempDir())
	if err != nil {
		t.Fatalf("load migration fixture %s: %v", filename, err)
	}
	return loaded
}

func repoIDSet(repos []config.Repo) map[string]bool {
	result := make(map[string]bool, len(repos))
	for _, repo := range repos {
		result[repo.ID] = true
	}
	return result
}

func migrationCommandRepoIDs(command string) []string {
	words := strings.Fields(command)
	var result []string
	for index, word := range words {
		var value string
		switch {
		case word == "--repo" && index+1 < len(words):
			value = words[index+1]
		case strings.HasPrefix(word, "--repo="):
			value = strings.TrimPrefix(word, "--repo=")
		}
		for _, item := range strings.Split(value, ",") {
			if item = strings.TrimSpace(item); item != "" {
				result = append(result, item)
			}
		}
	}
	return result
}

func readMigrationFamilyContracts(t *testing.T, filename string) map[string]migrationFamilyContract {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.Comma = '\t'
	reader.FieldsPerRecord = 5
	reader.Comment = '#'
	header, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(header, "\t") != "family\tdispositions\tcoverage\tevidence\tboundary" {
		t.Fatalf("unexpected migration family contract header: %v", header)
	}
	body, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	firstLine := strings.SplitN(string(body), "\n", 2)[0]
	if firstLine != migrationFamilyContractSchema {
		t.Fatalf("migration family contract schema=%q want=%q", firstLine, migrationFamilyContractSchema)
	}
	contracts := make(map[string]migrationFamilyContract)
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		contract := migrationFamilyContract{
			family:       record[0],
			dispositions: splitSortedCSV(record[1]),
			coverage:     record[2],
			evidence:     splitCSV(record[3]),
			boundary:     strings.TrimSpace(record[4]),
		}
		if !legacyFamilyRow.MatchString(contract.family) {
			t.Fatalf("invalid migration family contract id %q", contract.family)
		}
		if _, exists := contracts[contract.family]; exists {
			t.Fatalf("duplicate migration family contract %s", contract.family)
		}
		if contract.boundary == "" {
			t.Fatalf("migration family %s has an empty evidence boundary", contract.family)
		}
		switch contract.coverage {
		case "disposition-contract", "local-cli", "provider-protocol", "local-cli+provider-protocol":
		default:
			t.Fatalf("migration family %s has unknown coverage %q", contract.family, contract.coverage)
		}
		contracts[contract.family] = contract
	}
	return contracts
}

func migrationRowsByFamily(t *testing.T, rows []migrationLedgerRow, families map[string][]string) map[string][]migrationLedgerRow {
	t.Helper()
	byTarget := make(map[string]migrationLedgerRow, len(rows))
	for _, row := range rows {
		prefix := strings.SplitN(row.id, "-", 2)[0]
		byTarget[prefix+"\x00"+row.target] = row
	}
	result := make(map[string][]migrationLedgerRow, len(families))
	for family, targets := range families {
		prefix := map[string]string{"R": "ROOT", "A": "APT", "Y": "YUM", "D": "DKR"}[family[:1]]
		for _, target := range targets {
			row, exists := byTarget[prefix+"\x00"+target]
			if !exists {
				t.Fatalf("family %s refers to unknown target %s/%s", family, prefix, target)
			}
			result[family] = append(result[family], row)
		}
	}
	return result
}

func migrationRowDispositions(rows []migrationLedgerRow) []string {
	result := make([]string, 0, len(rows))
	for _, row := range rows {
		result = append(result, row.disposition)
	}
	return result
}

func migrationRowsContainVerb(rows []migrationLedgerRow, wanted string) bool {
	for _, row := range rows {
		if row.disposition != "sow-cli" {
			continue
		}
		for _, command := range migrationCommands(row.replacement) {
			words := strings.Fields(command)
			if len(words) >= 2 && words[1] == wanted {
				return true
			}
		}
	}
	return false
}

func assertMigrationFamilyCommandsCovered(t *testing.T, family string, rows []migrationLedgerRow, contract migrationFamilyContract, selector *config.Config) {
	t.Helper()
	var tests []string
	coveredCompatibilityArches := make(map[string]bool)
	for _, item := range contract.evidence {
		if strings.HasPrefix(item, "Test") {
			if strings.Contains(item, "Help") || strings.Contains(item, "Selector") {
				t.Errorf("family %s uses %s as business-equivalence evidence", family, item)
				continue
			}
			tests = append(tests, item)
			for arch := range migrationEvidenceCapabilities[item].compatibilityArches {
				coveredCompatibilityArches[arch] = true
			}
		}
	}
	if len(tests) == 0 {
		t.Errorf("family %s has sow-cli rows but no executable Go E2E evidence", family)
		return
	}
	requiredCompatibilityArches := make(map[string]bool)
	for _, row := range rows {
		if row.disposition != "sow-cli" {
			continue
		}
		commands := migrationCommands(row.replacement)
		if len(commands) == 0 {
			t.Errorf("family %s row %s has no SOW command", family, row.id)
			continue
		}
		for _, command := range commands {
			words := strings.Fields(command)
			if len(words) < 2 || words[0] != "sow" || strings.HasPrefix(words[1], "-") {
				t.Errorf("family %s row %s has non-business command %q", family, row.id, command)
				continue
			}
			verb := migrationCommandBusinessVerb(command)
			if strings.HasPrefix(verb, "compatibility/") {
				projections, err := migrationCompatibilityCommandProjections(words, selector)
				if err != nil {
					t.Errorf("family %s row %s compatibility command %q: %v", family, row.id, command, err)
					continue
				}
				for _, projection := range projections {
					requiredCompatibilityArches[projection.Source.Arch] = true
				}
			}
			repoTypes, err := migrationCommandRepoTypes(command, selector)
			if err != nil {
				t.Errorf("family %s row %s command %q: %v", family, row.id, command, err)
				continue
			}
			for _, repoType := range repoTypes {
				covered, providerCovered := false, false
				for _, name := range tests {
					capability := migrationEvidenceCapabilities[name]
					if capability.verbs[verb] && capability.repoType[repoType] {
						covered = true
						providerCovered = providerCovered || capability.provider
					}
				}
				if !covered {
					t.Errorf("family %s row %s command %q lacks real %s %s E2E evidence", family, row.id, command, repoType, verb)
				}
				if verb == "publish" && !providerCovered {
					t.Errorf("family %s row %s command %q lacks local provider-protocol evidence", family, row.id, command)
				}
			}
		}
	}
	for _, arch := range sortedKeys(requiredCompatibilityArches) {
		if !coveredCompatibilityArches[arch] {
			t.Errorf("family %s compatibility commands require physical %s evidence", family, arch)
		}
	}
}

func migrationCommandRepoTypes(command string, cfg *config.Config) ([]string, error) {
	words := strings.Fields(command)
	if len(words) >= 3 && words[0] == "sow" && words[1] == "compatibility" {
		if !strings.HasPrefix(words[2], "yum-") {
			return nil, fmt.Errorf("unknown compatibility command %s", words[2])
		}
		if _, err := migrationCompatibilityCommandProjections(words, cfg); err != nil {
			return nil, err
		}
		return []string{"yum"}, nil
	}
	ids := migrationCommandRepoIDs(command)
	if len(ids) == 0 {
		for _, repo := range cfg.Repos {
			ids = append(ids, repo.ID)
		}
	} else {
		expanded, err := cfg.ExpandRepoSelectors(ids)
		if err != nil {
			return nil, err
		}
		ids = expanded
	}
	types := make(map[string]bool)
	for _, id := range ids {
		repo, exists := cfg.RepoByName(id)
		if !exists {
			return nil, fmt.Errorf("unknown repository %s", id)
		}
		types[repo.Type] = true
	}
	return sortedKeys(types), nil
}

func migrationCommandBusinessVerb(command string) string {
	words := strings.Fields(command)
	if len(words) >= 3 && words[0] == "sow" && words[1] == "compatibility" {
		return words[1] + "/" + words[2]
	}
	if len(words) >= 2 && words[0] == "sow" {
		return words[1]
	}
	return ""
}

func assertMigrationEvidenceTestsExist(t *testing.T) {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	for _, filename := range files {
		body, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		source.Write(body)
	}
	for name := range migrationEvidenceCapabilities {
		if !strings.Contains(source.String(), "func "+name+"(") {
			t.Errorf("migration evidence test %s is not defined in internal/cli", name)
		}
	}
}

func splitCSV(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func splitSortedCSV(value string) []string {
	result := splitCSV(value)
	sort.Strings(result)
	return result
}

func uniqueSortedStrings(values []string) []string {
	return sortedKeys(migrationStringSet(values))
}

func migrationStringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func sortedKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func differenceStrings(left, right []string) []string {
	rightSet := migrationStringSet(right)
	var result []string
	for _, value := range left {
		if !rightSet[value] {
			result = append(result, value)
		}
	}
	return result
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
